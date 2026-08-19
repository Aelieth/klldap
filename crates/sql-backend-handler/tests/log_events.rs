// Own binary: the log sink is process-global, and the recorder must not see the
// library binary's concurrent tests.
use lldap_auth::opaque::server::generate_random_private_key;
use lldap_domain::{
    requests::{
        CreateAttributeRequest, CreateGroupRequest, CreateUserRequest, UpdateGroupRequest,
        UpdateUserRequest,
    },
    types::{Attribute, AttributeType, UserId},
};
use lldap_domain_handlers::{
    handler::{
        BindRequest, GroupBackendHandler, LoginHandler, PosixBackendHandler, SchemaBackendHandler,
        SystemConfigBackendHandler, UserBackendHandler,
    },
    logging::{LogKind, Protocol, RequestMeta, with_actor, with_request},
};
use lldap_sql_backend_handler::{
    PosixSettings, SqlBackendHandler, register_password, sql_tables::init_table,
};
use lldap_test_utils::recording_log::LogGuard;
use pretty_assertions::assert_eq;
use sea_orm::Database;
use serial_test::serial;
use std::net::{IpAddr, Ipv4Addr};

async fn handler() -> SqlBackendHandler {
    let mut options = sea_orm::ConnectOptions::new("sqlite::memory:");
    options.max_connections(1);
    let sql_pool = Database::connect(options).await.unwrap();
    init_table(&sql_pool).await.unwrap();
    SqlBackendHandler::new(generate_random_private_key(), sql_pool)
}

fn attribute(name: &str) -> CreateAttributeRequest {
    CreateAttributeRequest {
        name: name.into(),
        attribute_type: AttributeType::String,
        is_list: false,
        is_visible: true,
        is_editable: false,
    }
}

#[tokio::test]
#[serial]
async fn test_every_directory_write_records_a_log_event() {
    let handler = handler().await;
    let guard = LogGuard::install();
    let bob = UserId::new("bob");

    handler
        .create_user(CreateUserRequest {
            user_id: bob.clone(),
            email: "bob@example.com".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    handler
        .update_user(UpdateUserRequest {
            user_id: bob.clone(),
            email: Some("robert@example.com".into()),
            insert_attributes: vec![Attribute {
                name: "first_name".into(),
                value: "Bob".to_string().into(),
            }],
            ..Default::default()
        })
        .await
        .unwrap();
    register_password(&handler, bob.clone(), b"bobbybobbob")
        .await
        .unwrap();
    let devs = handler
        .create_group(CreateGroupRequest {
            display_name: "devs".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    handler.add_user_to_group(&bob, devs).await.unwrap();
    handler
        .update_group(UpdateGroupRequest {
            group_id: devs,
            display_name: Some("developers".into()),
            delete_attributes: vec![],
            insert_attributes: vec![],
        })
        .await
        .unwrap();
    handler.remove_user_from_group(&bob, devs).await.unwrap();
    handler
        .set_system_config("allowedous", r#"["people","groups","lab"]"#.to_owned())
        .await
        .unwrap();
    handler
        .add_user_attribute(attribute("nickname"))
        .await
        .unwrap();
    handler
        .delete_user_attribute(&"nickname".into())
        .await
        .unwrap();
    handler
        .add_group_attribute(attribute("motto"))
        .await
        .unwrap();
    handler
        .delete_group_attribute(&"motto".into())
        .await
        .unwrap();
    handler
        .add_user_object_class(&"posixAccount".into())
        .await
        .unwrap();
    handler
        .delete_user_object_class(&"posixAccount".into())
        .await
        .unwrap();
    handler
        .add_group_object_class(&"posixGroup".into())
        .await
        .unwrap();
    handler
        .delete_group_object_class(&"posixGroup".into())
        .await
        .unwrap();
    handler
        .set_posix_settings(PosixSettings::default())
        .await
        .unwrap();
    handler.reassign_gid_numbers().await.unwrap();
    handler.delete_group(devs).await.unwrap();
    handler.delete_user(&bob).await.unwrap();

    let events = guard.recorder().take_events();
    let posix_json = serde_json::to_string(&PosixSettings::default()).unwrap();
    let expected = vec![
        (LogKind::UserCreate, Some("bob"), None),
        (LogKind::UserUpdate, Some("bob"), Some("first_name, email")),
        (LogKind::PasswordChange, Some("bob"), None),
        (LogKind::GroupCreate, Some("devs"), None),
        (LogKind::MembershipAdd, Some("bob"), Some("devs")),
        (LogKind::GroupUpdate, Some("devs"), Some("display_name")),
        (LogKind::MembershipRemove, Some("bob"), Some("developers")),
        (
            LogKind::SystemConfigChange,
            Some("allowedous"),
            Some(r#"["people","groups","lab"]"#),
        ),
        (
            LogKind::SchemaChange,
            Some("nickname"),
            Some("add user attribute"),
        ),
        (
            LogKind::SchemaChange,
            Some("nickname"),
            Some("delete user attribute"),
        ),
        (
            LogKind::SchemaChange,
            Some("motto"),
            Some("add group attribute"),
        ),
        (
            LogKind::SchemaChange,
            Some("motto"),
            Some("delete group attribute"),
        ),
        (
            LogKind::SchemaChange,
            Some("posixAccount"),
            Some("add user object class"),
        ),
        (
            LogKind::SchemaChange,
            Some("posixAccount"),
            Some("delete user object class"),
        ),
        (
            LogKind::SchemaChange,
            Some("posixGroup"),
            Some("add group object class"),
        ),
        (
            LogKind::SchemaChange,
            Some("posixGroup"),
            Some("delete group object class"),
        ),
        (
            LogKind::SystemConfigChange,
            Some("posix_settings"),
            Some(posix_json.as_str()),
        ),
        (
            LogKind::PosixChange,
            Some("group gidnumber"),
            Some("reassign"),
        ),
        (LogKind::GroupDelete, Some("developers"), None),
        (LogKind::UserDelete, Some("bob"), None),
    ];
    assert_eq!(
        events
            .iter()
            .map(|e| (e.kind, e.target.as_deref(), e.detail.as_deref()))
            .collect::<Vec<_>>(),
        expected
    );
    assert!(events.iter().all(|e| e.success));
    assert!(
        events
            .iter()
            .all(|e| e.protocol == Protocol::System && e.actor.is_none() && e.peer.is_none()),
        "no request scope: system events without an actor"
    );
}

#[tokio::test]
#[serial]
async fn test_bind_records_the_claimed_user_and_the_request_scope() {
    let handler = handler().await;
    let bob = UserId::new("bob");
    handler
        .create_user(CreateUserRequest {
            user_id: bob.clone(),
            email: "bob@example.com".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    register_password(&handler, bob.clone(), b"bobbybobbob")
        .await
        .unwrap();
    let ldap_peer: IpAddr = "10.0.0.5".parse().unwrap();
    let guard = LogGuard::install();

    with_request(
        RequestMeta::ldap(None, Some(ldap_peer)),
        handler.bind(BindRequest {
            name: bob.clone(),
            password: "bobbybobbob".to_owned(),
        }),
    )
    .await
    .unwrap();
    with_request(
        RequestMeta::http(Some(Ipv4Addr::LOCALHOST.into()), Some("203.0.113.9".into())),
        handler.bind(BindRequest {
            name: bob.clone(),
            password: "wrong".to_owned(),
        }),
    )
    .await
    .unwrap_err();
    handler
        .bind(BindRequest {
            name: UserId::new("nobody"),
            password: "whatever".to_owned(),
        })
        .await
        .unwrap_err();
    let disabled = handler
        .create_group(CreateGroupRequest {
            display_name: "lldap_disabled".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    handler.add_user_to_group(&bob, disabled).await.unwrap();
    handler
        .bind(BindRequest {
            name: bob.clone(),
            password: "bobbybobbob".to_owned(),
        })
        .await
        .unwrap_err();

    let events = guard.recorder().take_events();
    let binds: Vec<_> = events.iter().filter(|e| e.kind == LogKind::Bind).collect();
    assert_eq!(binds.len(), 4);
    assert!(binds[0].success);
    assert_eq!(binds[0].actor.as_deref(), Some("bob"));
    assert_eq!(binds[0].protocol, Protocol::Ldap);
    assert_eq!(binds[0].peer.as_deref(), Some("10.0.0.5"));
    assert!(!binds[1].success);
    assert_eq!(binds[1].protocol, Protocol::Http);
    assert_eq!(binds[1].peer.as_deref(), Some("127.0.0.1"));
    assert_eq!(binds[1].forwarded_for.as_deref(), Some("203.0.113.9"));
    assert_eq!(binds[1].detail.as_deref(), Some("invalid credentials"));
    assert_eq!(binds[2].actor.as_deref(), Some("nobody"));
    assert_eq!(binds[2].detail.as_deref(), Some("unknown user"));
    assert_eq!(binds[2].protocol, Protocol::System);
    assert_eq!(binds[3].detail.as_deref(), Some("account disabled"));
}

#[tokio::test]
#[serial]
async fn test_password_change_carries_the_scoped_actor() {
    let handler = handler().await;
    let bob = UserId::new("bob");
    handler
        .create_user(CreateUserRequest {
            user_id: bob.clone(),
            email: "bob@example.com".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let guard = LogGuard::install();

    with_actor(
        Some(UserId::new("admin")),
        register_password(&handler, bob.clone(), b"bobbybobbob"),
    )
    .await
    .unwrap();

    let events = guard.recorder().take_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, LogKind::PasswordChange);
    assert_eq!(events[0].actor.as_deref(), Some("admin"));
    assert_eq!(events[0].target.as_deref(), Some("bob"));
    assert_eq!(
        events[0].to_string(),
        "✅ password_change bob by admin (system)"
    );
}

#[tokio::test]
#[serial]
async fn test_unknown_system_config_key_does_not_log_the_value() {
    let handler = handler().await;
    let guard = LogGuard::install();
    handler
        .set_system_config("future_secret", "hunter2".to_owned())
        .await
        .unwrap();
    let events = guard.recorder().take_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, LogKind::SystemConfigChange);
    assert_eq!(events[0].target.as_deref(), Some("future_secret"));
    assert_eq!(events[0].detail.as_deref(), Some("updated"));
}
