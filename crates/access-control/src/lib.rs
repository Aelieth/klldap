#![forbid(unsafe_code)]
use async_trait::async_trait;
use lldap_auth::access_control::{Permission, ValidationResults};
use lldap_auth::{login, registration};
use lldap_domain::{
    requests::{
        CreateAttributeRequest, CreateGroupRequest, CreateUserRequest, UpdateGroupRequest,
        UpdateUserRequest,
    },
    types::{
        AttributeName, Group, GroupDetails, GroupId, GroupName, LdapObjectClass, User,
        UserAndGroups, UserId,
    },
};
use lldap_domain_handlers::handler::{
    BackendHandler, GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter,
    LogBackendHandler, MfaBackendHandler, PosixBackendHandler, ReadSchemaBackendHandler,
    SchemaBackendHandler, SystemConfigBackendHandler, UserBackendHandler, UserListerBackendHandler,
    UserRequestFilter,
};
use lldap_domain_model::error::Result;
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::PublicSchema;
use std::collections::HashSet;
use tracing::debug;

#[async_trait]
pub trait UserReadableBackendHandler: ReadSchemaBackendHandler {
    async fn get_user_details(&self, user_id: &UserId) -> Result<User>;
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>>;
}

#[async_trait]
pub trait ReadonlyBackendHandler: UserReadableBackendHandler {
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>>;
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>>;
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails>;
}

#[async_trait]
pub trait UserWriteableBackendHandler: UserReadableBackendHandler {
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()>;
    async fn ensure_kerberos_principal_consistency(
        &self,
        user_id: &UserId,
        enabled: bool,
    ) -> Result<()>;
}

#[async_trait]
pub trait AdminBackendHandler:
    UserWriteableBackendHandler
    + ReadonlyBackendHandler
    + SchemaBackendHandler
    + SystemConfigBackendHandler
    + PosixBackendHandler
    + LogBackendHandler
    + OpaqueHandler
{
    async fn create_user(&self, request: CreateUserRequest) -> Result<()>;
    async fn delete_user(&self, user_id: &UserId) -> Result<()>;
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()>;
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()>;
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId>;
    async fn delete_group(&self, group_id: GroupId) -> Result<()>;
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()>;
    async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()>;
    async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()>;
    async fn add_user_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    async fn add_group_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()>;
    async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()>;
}

#[async_trait]
impl<Handler: BackendHandler> UserReadableBackendHandler for Handler {
    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        <Handler as UserBackendHandler>::get_user_details(self, user_id).await
    }
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>> {
        <Handler as UserBackendHandler>::get_user_groups(self, user_id).await
    }
}

#[async_trait]
impl<Handler: BackendHandler> ReadonlyBackendHandler for Handler {
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        <Handler as UserListerBackendHandler>::list_users(self, filters, get_groups).await
    }
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        <Handler as GroupListerBackendHandler>::list_groups(self, filters).await
    }
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails> {
        <Handler as GroupBackendHandler>::get_group_details(self, group_id).await
    }
}

#[async_trait]
impl<Handler: BackendHandler> UserWriteableBackendHandler for Handler {
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        <Handler as UserBackendHandler>::update_user(self, request).await
    }
    async fn ensure_kerberos_principal_consistency(
        &self,
        user_id: &UserId,
        enabled: bool,
    ) -> Result<()> {
        <Handler as UserBackendHandler>::ensure_kerberos_principal_consistency(
            self, user_id, enabled,
        )
        .await
    }
}

#[async_trait]
impl<Handler: BackendHandler + OpaqueHandler> AdminBackendHandler for Handler {
    async fn create_user(&self, request: CreateUserRequest) -> Result<()> {
        <Handler as UserBackendHandler>::create_user(self, request).await
    }
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        <Handler as UserBackendHandler>::delete_user(self, user_id).await
    }
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        <Handler as UserBackendHandler>::add_user_to_group(self, user_id, group_id).await
    }
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        <Handler as UserBackendHandler>::remove_user_from_group(self, user_id, group_id).await
    }
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()> {
        <Handler as GroupBackendHandler>::update_group(self, request).await
    }
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId> {
        <Handler as GroupBackendHandler>::create_group(self, request).await
    }
    async fn delete_group(&self, group_id: GroupId) -> Result<()> {
        <Handler as GroupBackendHandler>::delete_group(self, group_id).await
    }
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        <Handler as SchemaBackendHandler>::add_user_attribute(self, request).await
    }
    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        <Handler as SchemaBackendHandler>::add_group_attribute(self, request).await
    }
    async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()> {
        <Handler as SchemaBackendHandler>::delete_user_attribute(self, name).await
    }
    async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()> {
        <Handler as SchemaBackendHandler>::delete_group_attribute(self, name).await
    }
    async fn add_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        <Handler as SchemaBackendHandler>::add_user_object_class(self, name).await
    }
    async fn add_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        <Handler as SchemaBackendHandler>::add_group_object_class(self, name).await
    }
    async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        <Handler as SchemaBackendHandler>::delete_user_object_class(self, name).await
    }
    async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        <Handler as SchemaBackendHandler>::delete_group_object_class(self, name).await
    }
}

pub struct AccessControlledBackendHandler<Handler> {
    handler: Handler,
}

impl<Handler: Clone> Clone for AccessControlledBackendHandler<Handler> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
        }
    }
}

impl<Handler> AccessControlledBackendHandler<Handler> {
    pub fn unsafe_get_handler(&self) -> &Handler {
        &self.handler
    }
}

impl<Handler: BackendHandler + OpaqueHandler> AccessControlledBackendHandler<Handler> {
    pub fn new(handler: Handler) -> Self {
        Self { handler }
    }

    pub fn get_schema_only_handler(
        &self,
        _validation_result: &ValidationResults,
    ) -> Option<&impl ReadSchemaBackendHandler> {
        Some(&self.handler)
    }

    pub fn get_admin_handler<'a>(
        &'a self,
        validation_results: &ValidationResults,
    ) -> Option<&'a (impl AdminBackendHandler + Send + Sync + 'a)> {
        validation_results.is_admin().then_some(&self.handler)
    }

    pub fn get_readonly_handler<'a>(
        &'a self,
        validation_result: &ValidationResults,
    ) -> Option<&'a (impl ReadonlyBackendHandler + 'a)> {
        validation_result.can_read_all().then_some(&self.handler)
    }

    pub fn get_writeable_handler<'a>(
        &'a self,
        validation_result: &ValidationResults,
        user_id: UserId, // owned UserId (no &)
    ) -> Option<&'a (impl UserWriteableBackendHandler + OpaqueHandler + 'a)> {
        validation_result
            .can_write(&user_id)
            .then_some(&self.handler)
    }

    pub fn get_readable_handler<'a>(
        &'a self,
        validation_result: &ValidationResults,
        user_id: UserId, // owned UserId (no &)
    ) -> Option<&'a (impl UserReadableBackendHandler + 'a)> {
        validation_result
            .can_read(&user_id)
            .then_some(&self.handler)
    }

    pub fn get_mfa_reset_handler<'a>(
        &'a self,
        validation_result: &ValidationResults,
        user_id: &UserId,
        user_is_admin: bool,
    ) -> Option<&'a (impl MfaBackendHandler + 'a)> {
        validation_result
            .can_reset_mfa(user_id, user_is_admin)
            .then_some(&self.handler)
    }

    // These only ever target the authenticated user, so there is no check.
    pub fn get_mfa_self_handler(&self) -> &(impl MfaBackendHandler + '_) {
        &self.handler
    }

    pub fn get_user_restricted_lister_handler(
        &self,
        validation_result: &ValidationResults,
    ) -> UserRestrictedListerBackendHandler<'_, Handler> {
        UserRestrictedListerBackendHandler {
            handler: &self.handler,
            user_filter: if validation_result.can_read_all() {
                None
            } else {
                debug!("Unprivileged search, limiting results");
                Some(validation_result.user.clone())
            },
        }
    }

    pub async fn get_permissions_for_user(&self, user_id: UserId) -> Result<ValidationResults> {
        let user_groups = self.handler.get_user_groups(&user_id).await?;
        Ok(self.get_permissions_from_groups(user_id, user_groups.iter().map(|g| &g.display_name)))
    }

    pub fn get_permissions_from_groups<Groups, T>(
        &self,
        user_id: UserId,
        groups: Groups,
    ) -> ValidationResults
    where
        Groups: Iterator<Item = T> + Clone,
        T: AsRef<GroupName>,
    {
        let is_in_group = |name: GroupName| groups.clone().any(|g| *g.as_ref() == name);
        ValidationResults {
            user: user_id,
            permission: if is_in_group("lldap_admin".into()) {
                Permission::Admin
            } else if is_in_group("lldap_password_manager".into()) {
                Permission::PasswordManager
            } else if is_in_group("lldap_strict_readonly".into()) {
                Permission::Readonly
            } else {
                Permission::Regular
            },
        }
    }

    /// No permission check: the LDAP password path calls this only after `can_change_password`.
    pub async fn ensure_kerberos_principal_consistency(
        &self,
        user_id: &UserId,
        enabled: bool,
    ) -> Result<()> {
        self.handler
            .ensure_kerberos_principal_consistency(user_id, enabled)
            .await
    }
}

pub struct UserRestrictedListerBackendHandler<'a, Handler> {
    handler: &'a Handler,
    user_filter: Option<UserId>,
}

fn restrict_to_visible_attributes(schema: &mut PublicSchema) {
    schema.0.user_attributes.attributes.retain(|a| a.is_visible);
    schema
        .0
        .group_attributes
        .attributes
        .retain(|a| a.is_visible);
}

#[async_trait]
impl<Handler: ReadSchemaBackendHandler + Sync> ReadSchemaBackendHandler
    for UserRestrictedListerBackendHandler<'_, Handler>
{
    async fn get_schema(&self) -> Result<PublicSchema> {
        let mut public_schema = self.handler.get_schema().await?;
        if self.user_filter.is_some() {
            restrict_to_visible_attributes(&mut public_schema);
        }
        Ok(public_schema)
    }
}

#[async_trait]
impl<Handler: UserListerBackendHandler + Sync> UserListerBackendHandler
    for UserRestrictedListerBackendHandler<'_, Handler>
{
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        let user_filter = self
            .user_filter
            .as_ref()
            .map(|u| UserRequestFilter::UserId(u.clone()));
        let filters = match (filters, user_filter) {
            (None, None) => None,
            (None, u) => u,
            (f, None) => f,
            (Some(f), Some(u)) => Some(UserRequestFilter::And(vec![f, u])),
        };
        self.handler.list_users(filters, get_groups).await
    }
}

#[async_trait]
impl<Handler: GroupListerBackendHandler + Sync> GroupListerBackendHandler
    for UserRestrictedListerBackendHandler<'_, Handler>
{
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        let group_filter = self
            .user_filter
            .as_ref()
            .map(|u| GroupRequestFilter::Member(u.clone()));
        let filters = match (filters, group_filter) {
            (None, None) => None,
            (None, u) => u,
            (f, None) => f,
            (Some(f), Some(u)) => Some(GroupRequestFilter::And(vec![f, u])),
        };
        self.handler.list_groups(filters).await
    }
}

#[async_trait]
pub trait UserAndGroupListerBackendHandler:
    UserListerBackendHandler + GroupListerBackendHandler
{
    fn user_filter(&self) -> &Option<UserId>;
}

#[async_trait]
impl<Handler: GroupListerBackendHandler + UserListerBackendHandler + Sync>
    UserAndGroupListerBackendHandler for UserRestrictedListerBackendHandler<'_, Handler>
{
    fn user_filter(&self) -> &Option<UserId> {
        &self.user_filter
    }
}

#[async_trait]
impl<Inner: OpaqueHandler + Send + Sync> OpaqueHandler for AccessControlledBackendHandler<Inner> {
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse> {
        self.handler.login_start(request).await
    }

    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<UserId> {
        self.handler.login_finish(request).await
    }

    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse> {
        self.handler.registration_start(request).await
    }

    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<()> {
        self.handler.registration_finish(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restrict_to_visible_attributes_drops_hidden_entries() {
        let mut schema = PublicSchema::get();
        assert!(
            schema
                .user_attributes()
                .get_by_name_or_alias("krbprincipalname")
                .is_some(),
            "precondition: krbprincipalname is in the full schema"
        );
        restrict_to_visible_attributes(&mut schema);
        assert!(
            schema
                .user_attributes()
                .get_by_name_or_alias("krbprincipalname")
                .is_none(),
            "hidden krbprincipalname must be dropped for restricted users"
        );
        assert!(
            schema
                .user_attributes()
                .get_by_name_or_alias("mail")
                .is_some(),
            "visible mail must be retained"
        );
        assert!(
            schema
                .user_attributes()
                .attributes
                .iter()
                .all(|a| a.is_visible)
        );
        assert!(
            schema
                .group_attributes()
                .attributes
                .iter()
                .all(|a| a.is_visible)
        );
    }
}
