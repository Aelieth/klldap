#![forbid(unsafe_code)]
use async_trait::async_trait;
use lldap_domain::{
    requests::{
        CreateAttributeRequest, CreateGroupRequest, CreateUserRequest, UpdateGroupRequest,
        UpdateUserRequest,
    },
    types::{
        AttributeName, Group, GroupDetails, GroupId, LdapObjectClass, User, UserAndGroups, UserId,
    },
};
use lldap_domain_handlers::handler::{
    BackendHandler, BindRequest, GroupBackendHandler, GroupListerBackendHandler,
    GroupRequestFilter, LoginHandler, PosixBackendHandler, PosixSettings, ReadSchemaBackendHandler,
    SchemaBackendHandler, SystemConfigBackendHandler, UserBackendHandler, UserListerBackendHandler,
    UserRequestFilter,
};
use lldap_domain_model::error::Result;
use lldap_opaque_handler::{OpaqueHandler, login, registration};
use lldap_schema::PublicSchema;
use std::collections::HashSet;

// Re-export the avatar test helpers so other crates can use them easily
pub use lldap_domain::images::{make_test_avatar_value, make_test_jpeg_bytes};

mockall::mock! {
    pub TestBackendHandler{}
    impl Clone for TestBackendHandler {
        fn clone(&self) -> Self;
    }
    #[async_trait]
    impl LoginHandler for TestBackendHandler {
        async fn bind(&self, request: BindRequest) -> Result<()>;
    }
    #[async_trait]
    impl GroupListerBackendHandler for TestBackendHandler {
        async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
    }
    #[async_trait]
    impl GroupBackendHandler for TestBackendHandler {
        async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
        async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
        async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId>;
        async fn delete_group(&self, group_id: GroupId) -> Result<()>;
    }
    #[async_trait]
    impl UserListerBackendHandler for TestBackendHandler {
        async fn list_users(&self, filters: Option<UserRequestFilter>, get_groups: bool) -> Result<Vec<UserAndGroups>>;
    }
    #[async_trait]
    impl UserBackendHandler for TestBackendHandler {
        async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
        async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
        async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
        async fn delete_user(&self, user_id: &UserId) -> Result<()>;
        async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
        async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
        async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    }
    #[async_trait]
    impl ReadSchemaBackendHandler for TestBackendHandler {
        async fn get_schema(&self) -> Result<PublicSchema>;
    }
    #[async_trait]
    impl SchemaBackendHandler for TestBackendHandler {
        async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
        async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
        async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()>;
        async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()>;
        async fn add_user_object_class(&self, request: &LdapObjectClass) -> Result<()>;
        async fn add_group_object_class(&self, request: &LdapObjectClass) -> Result<()>;
        async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()>;
        async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    }
    #[async_trait]
    impl BackendHandler for TestBackendHandler {}
    #[async_trait]
    impl OpaqueHandler for TestBackendHandler {
        async fn login_start(
            &self, request: login::ClientLoginStartRequest
        ) -> Result<login::ServerLoginStartResponse>;
        async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId>;
        async fn registration_start(
            &self, request: registration::ClientRegistrationStartRequest
        ) -> Result<registration::ServerRegistrationStartResponse>;
        async fn registration_finish(
            &self, request: registration::ClientRegistrationFinishRequest
        ) -> Result<()>;
    }
    #[async_trait]
    impl PosixBackendHandler for TestBackendHandler {
        async fn get_posix_settings(&self) -> Result<PosixSettings>;
        async fn set_posix_settings(&self, settings: PosixSettings) -> Result<()>;
        async fn reassign_gid_numbers(&self) -> Result<()>;
        async fn reassign_user_uid_numbers(&self) -> Result<()>;
        async fn reassign_user_gid_numbers(&self) -> Result<()>;
        async fn reassign_user_homedirectories(&self) -> Result<()>;
        async fn reassign_user_loginshells(&self) -> Result<()>;
    }

    #[async_trait]
    impl SystemConfigBackendHandler for TestBackendHandler {
        async fn get_allowed_ous(&self) -> Result<Vec<String>>;
        async fn set_system_config(&self, key: &str, value: String) -> Result<()>;
        async fn ensure_kerberos_principal_consistency(
            &self, user_id: &UserId, enabled: bool,
        ) -> Result<()>;
    }
}

pub fn setup_default_schema(mock: &mut MockTestBackendHandler) {
    mock.expect_get_schema()
        .returning(|| Ok(PublicSchema::get()));
}

/// Robust default mock for all LDAP tests.
/// This provides sensible defaults so individual tests only need to override what they assert on.
pub fn setup_default_ldap_mock(mock: &mut MockTestBackendHandler) {
    setup_default_schema(mock);

    // New OU system
    mock.expect_get_allowed_ous()
        .returning(|| Ok(vec!["people".to_string(), "groups".to_string()]));

    // Default user details
    mock.expect_get_user_details().returning(|uid| {
        Ok(User {
            user_id: uid.clone(),
            email: format!("{}@example.com", uid.as_str()).into(),
            display_name: None,
            creation_date: chrono::Utc::now().naive_utc(),
            modified_date: chrono::Utc::now().naive_utc(),
            password_modified_date: chrono::Utc::now().naive_utc(),
            uuid: lldap_domain::types::Uuid::from_name_and_date(
                uid.as_str(),
                &chrono::Utc::now().naive_utc(),
            ),
            attributes: vec![],
            krb_principal_name: None,
        })
    });

    // Default empty groups (most tests expect this)
    mock.expect_get_user_groups()
        .returning(|_| Ok(HashSet::new()));
}
