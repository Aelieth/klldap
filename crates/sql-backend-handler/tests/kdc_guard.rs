// Own binary: the Kerberos backend is process-global, and a not-ready one would fail every
// concurrent write test in the library binary.
use lldap_auth::opaque::server::generate_random_private_key;
use lldap_domain::{
    requests::{CreateAttributeRequest, CreateGroupRequest, CreateUserRequest},
    types::{AttributeType, UserId},
};
use lldap_domain_handlers::handler::{
    GroupBackendHandler, PosixBackendHandler, SchemaBackendHandler, UserBackendHandler,
    UserListerBackendHandler,
};
use lldap_domain_model::error::DomainError;
use lldap_sql_backend_handler::{
    PosixSettings, SqlBackendHandler, register_password, sql_tables::init_table,
};
use lldap_test_utils::recording_kerberos::{DEGRADED_CAUSE, DegradedGuard, NotReadyGuard};
use sea_orm::Database;

#[tokio::test]
async fn test_directory_writes_wait_for_the_kdc() {
    let sql_pool = Database::connect("sqlite::memory:").await.unwrap();
    init_table(&sql_pool).await.unwrap();
    let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
    handler
        .create_user(CreateUserRequest {
            user_id: UserId::new("bob"),
            email: "bob@bob.bob".into(),
            ..Default::default()
        })
        .await
        .unwrap();

    let _kdc = NotReadyGuard::install();
    let refused = handler
        .create_group(CreateGroupRequest {
            display_name: "late".into(),
            ..Default::default()
        })
        .await;
    assert!(
        matches!(refused, Err(DomainError::KdcUnavailable(_))),
        "{refused:?}"
    );
    let refused = register_password(&handler, UserId::new("bob"), b"newpass").await;
    assert!(
        refused.is_err(),
        "password registration must wait for the KDC"
    );
    assert_eq!(handler.list_users(None, false).await.unwrap().len(), 1);
    drop(_kdc);

    let _kdc = DegradedGuard::install();
    let refused = handler
        .create_group(CreateGroupRequest {
            display_name: "late".into(),
            ..Default::default()
        })
        .await;
    assert!(
        matches!(&refused, Err(DomainError::KdcUnavailable(cause)) if cause == DEGRADED_CAUSE),
        "{refused:?}"
    );
    drop(_kdc);

    handler
        .create_group(CreateGroupRequest {
            display_name: "late".into(),
            ..Default::default()
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_in_directory_only_a_write_that_touches_no_principal_goes_on() {
    let sql_pool = Database::connect("sqlite::memory:").await.unwrap();
    init_table(&sql_pool).await.unwrap();
    let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
    let bob = UserId::new("bob");
    let _kdc = DegradedGuard::install_directory_only();
    let created = handler
        .create_user(CreateUserRequest {
            user_id: bob.clone(),
            email: "bob@bob.bob".into(),
            ..Default::default()
        })
        .await;
    let group = handler
        .create_group(CreateGroupRequest {
            display_name: "open".into(),
            ..Default::default()
        })
        .await
        .expect("a group is created in directory-only");
    let nickname = CreateAttributeRequest {
        name: "nickname".into(),
        attribute_type: AttributeType::String,
        is_list: false,
        is_visible: true,
        is_editable: true,
    };
    let member = handler.add_user_to_group(&bob, group).await;
    let posix = handler.set_posix_settings(PosixSettings::default()).await;
    let schema = handler.add_user_attribute(nickname).await;
    let password = register_password(&handler, bob.clone(), b"newpass").await;
    let no_member = handler.remove_user_from_group(&bob, group).await;
    let no_group = handler.delete_group(group).await;
    let went_on = [
        ("user", created.is_ok()),
        ("member", member.is_ok()),
        ("POSIX settings", posix.is_ok()),
        ("schema", schema.is_ok()),
        ("password", password.is_ok()),
        ("member removed", no_member.is_ok()),
        ("group deleted", no_group.is_ok()),
    ];
    assert!(went_on.iter().all(|(_, ok)| *ok), "{went_on:?}");
}
