// Own binary: the Kerberos backend is process-global, and a not-ready one would fail every
// concurrent write test in the library binary.
use lldap_auth::opaque::server::generate_random_private_key;
use lldap_domain::{
    requests::{CreateGroupRequest, CreateUserRequest},
    types::UserId,
};
use lldap_domain_handlers::handler::{
    GroupBackendHandler, UserBackendHandler, UserListerBackendHandler,
};
use lldap_domain_model::error::DomainError;
use lldap_sql_backend_handler::{SqlBackendHandler, register_password, sql_tables::init_table};
use lldap_test_utils::recording_kerberos::NotReadyGuard;
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

    handler
        .create_group(CreateGroupRequest {
            display_name: "late".into(),
            ..Default::default()
        })
        .await
        .unwrap();
}
