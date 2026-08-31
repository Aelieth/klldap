pub mod helpers;
pub mod inputs;
mod kerberos;
mod keycloak;
mod mfa;
mod ou;
mod posix;

pub use inputs::{
    AttributeValue, CreateGroupInput, CreateUserInput, MfaEnrollmentStart, Success,
    UpdateGroupInput, UpdateUserInput,
};

use crate::api::{Context, FullHandler, field_error_callback};
use crate::query::GraphQLAttributeType;
use anyhow::anyhow;
use helpers::{
    UnpackedAttributes, consolidate_attributes, create_group_with_details, deserialize_attribute,
    unpack_attributes,
};
use juniper::{FieldError, FieldResult, graphql_object};
use kerberos::ExportKeytabForKeycloakResponse;
use keycloak::{
    PushRealmResponse, PushRealmToKeycloakInput, SaveKeycloakConfigInput,
    SaveKeycloakConfigResponse, TestKeycloakConnectionInput, TestKeycloakConnectionResponse,
};
use lldap_access_control::{
    AdminBackendHandler, ReadonlyBackendHandler, UserReadableBackendHandler,
    UserWriteableBackendHandler,
};
use lldap_domain::{
    requests::{CreateAttributeRequest, CreateUserRequest, UpdateGroupRequest, UpdateUserRequest},
    types::{
        Attribute, AttributeName, Email, GroupId, LdapObjectClass, UserId, kerberos_sync_enabled,
    },
};
use lldap_domain_handlers::handler::{BackendHandler, ReadSchemaBackendHandler, UserRequestFilter};
use lldap_domain_handlers::kerberos::kerberos_backend;
use lldap_domain_handlers::mfa::is_protected_group;
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::schema::AttributeList;
use lldap_validation::attributes::{ALLOWED_CHARACTERS_DESCRIPTION, validate_attribute_name};
use posix::{PosixSettingsInput, PosixSettingsResponse};
use std::sync::Arc;
use tracing::{Instrument, debug, debug_span, info, warn};

#[derive(PartialEq, Eq, Debug)]
/// The top-level GraphQL mutation type.
pub struct Mutation<Handler: BackendHandler + OpaqueHandler> {
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

impl<Handler: BackendHandler + OpaqueHandler> Default for Mutation<Handler> {
    fn default() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: FullHandler + OpaqueHandler> Mutation<Handler> {
    async fn create_user(
        context: &Context<Handler>,
        user: CreateUserInput,
    ) -> FieldResult<super::query::User<Handler>> {
        let span = debug_span!("[GraphQL mutation] create_user");
        span.in_scope(|| debug!("{:?}", &user.id));
        let user_id = UserId::new(&user.id);
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized user creation"))?;
        let schema = handler.get_schema().await?;
        let consolidated_attributes = consolidate_attributes(
            user.attributes.unwrap_or_default(),
            user.first_name,
            user.last_name,
            user.avatar,
            &schema,
        );
        let ou_value = consolidated_attributes
            .iter()
            .find(|a| schema.resolve_user_canonical_name(&a.name) == Some("ou"))
            .and_then(|a| a.value.first().cloned())
            .unwrap_or_else(|| "people".to_string());
        let attributes_for_unpack: Vec<_> = consolidated_attributes
            .into_iter()
            .filter(|a| schema.resolve_user_canonical_name(&a.name) != Some("ou"))
            .collect();
        let UnpackedAttributes {
            email,
            display_name,
            attributes: unpacked_attributes,
        } = unpack_attributes(attributes_for_unpack, &schema, true)?;
        // ou is readonly for clients, so it is placed after the permission checks.
        let mut attributes = unpacked_attributes;
        attributes.push(Attribute {
            name: "ou".into(),
            value: ou_value.into(),
        });
        handler
            .create_user(CreateUserRequest {
                user_id: user_id.clone(),
                email: user
                    .email
                    .map(Email::from)
                    .or(email)
                    .ok_or_else(|| anyhow!("Email is required when creating a new user"))?,
                display_name: user.display_name.or(display_name),
                attributes,
            })
            .instrument(span.clone())
            .await?;
        let user_details = handler.get_user_details(&user_id).instrument(span).await?;
        super::query::User::<Handler>::from_user(user_details, Arc::new(schema))
    }

    async fn set_user_password(
        context: &Context<Handler>,
        user_id: String,
        password: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] set_user_password");
        span.in_scope(|| debug!("Setting password for user: {}", &user_id));
        let target_user_id = UserId::new(&user_id);
        let handler = context
            .get_writeable_handler(target_user_id.clone())
            .ok_or_else(field_error_callback(&span, "Unauthorized password set"))?;
        lldap_opaque_handler::register_password(
            handler,
            target_user_id.clone(),
            password.as_bytes(),
        )
        .await
        .map_err(|e| anyhow!("Password registration failed: {e}"))?;
        let user = handler
            .get_user_details(&target_user_id)
            .await
            .map_err(|e| anyhow!("Failed to fetch user for Kerberos sync check: {e}"))?;
        let sync_enabled = kerberos_sync_enabled(&user.attributes);
        if let Err(e) = kerberos_backend().sync_if_enabled(sync_enabled, &user_id, &password) {
            warn!("Kerberos sync failed after password set: {e}");
        } else if sync_enabled {
            info!("Kerberos principal synced for user {user_id}");
        }
        if let Err(e) = handler
            .ensure_kerberos_principal_consistency(&target_user_id, sync_enabled)
            .await
        {
            warn!("Failed to record Kerberos principal name for {target_user_id}: {e}");
        }
        // A first password for an already-disabled user would otherwise mint a live principal.
        if sync_enabled
            && let Ok(groups) = handler.get_user_groups(&target_user_id).await
            && groups
                .iter()
                .any(|g| g.display_name == "lldap_disabled".into())
        {
            kerberos_backend().reassert_disabled(&user_id);
        }
        Ok(Success::new())
    }

    async fn create_group(
        context: &Context<Handler>,
        name: Option<String>,
        group: Option<CreateGroupInput>,
    ) -> FieldResult<super::query::Group<Handler>> {
        let span = debug_span!("[GraphQL mutation] create_group");
        span.in_scope(|| {
            debug!(?name, ?group);
        });
        let group = match (name, group) {
            (Some(display_name), None) => CreateGroupInput {
                display_name,
                attributes: None,
            },
            (None, Some(group)) => group,
            _ => {
                return Err("createGroup requires exactly one of `name` and `group`".into());
            }
        };
        create_group_with_details(context, group, span).await
    }

    async fn create_group_with_details(
        context: &Context<Handler>,
        request: CreateGroupInput,
    ) -> FieldResult<super::query::Group<Handler>> {
        let span = debug_span!("[GraphQL mutation] create_group_with_details");
        span.in_scope(|| {
            debug!(?request);
        });
        create_group_with_details(context, request, span).await
    }

    async fn update_user(
        context: &Context<Handler>,
        user: UpdateUserInput,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] update_user");
        span.in_scope(|| debug!(?user.id));
        let user_id = UserId::new(&user.id);
        let handler = context
            .get_writeable_handler(user_id.clone())
            .ok_or_else(field_error_callback(&span, "Unauthorized user update"))?;
        let is_admin = context.validation_result.is_admin();
        let schema = handler.get_schema().await?;
        let consolidated_attributes = consolidate_attributes(
            user.insert_attributes.unwrap_or_default(),
            user.first_name,
            user.last_name,
            user.avatar,
            &schema,
        );
        let mut delete_attributes: Vec<String> = user.remove_attributes.unwrap_or_default();
        // ou is managed through the OU mutations, never edited directly.
        delete_attributes.retain(|attr| schema.resolve_user_canonical_name(attr) != Some("ou"));
        let UnpackedAttributes {
            email,
            display_name,
            attributes: insert_attributes,
        } = unpack_attributes(
            consolidated_attributes
                .into_iter()
                .filter(|a| !delete_attributes.contains(&a.name))
                .collect(),
            &schema,
            is_admin,
        )?;
        handler
            .update_user(UpdateUserRequest {
                user_id: user_id.clone(),
                email: user.email.map(Into::into).or(email),
                display_name: user.display_name.or(display_name),
                delete_attributes: delete_attributes
                    .clone()
                    .into_iter()
                    .filter(|attr| attr != "mail" && attr.to_lowercase() != "displayname")
                    .map(AttributeName::from)
                    .collect(),
                insert_attributes: insert_attributes.clone(),
            })
            .instrument(span.clone())
            .await?;
        Ok(Success::new())
    }

    async fn update_group(
        context: &Context<Handler>,
        group: UpdateGroupInput,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] update_group");
        span.in_scope(|| {
            debug!(?group.id);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized group update"))?;
        let new_display_name = group.display_name.clone().or_else(|| {
            group.insert_attributes.as_ref().and_then(|a| {
                a.iter()
                    .find(|attr| attr.name == "displayname")
                    .map(|attr| attr.value[0].clone())
            })
        });
        if new_display_name.is_some()
            && let Ok(details) = handler.get_group_details(GroupId(group.id)).await
            && is_protected_group(details.display_name.as_str(), context.mfa_policy)
        {
            span.in_scope(|| debug!("Cannot rename built-in group '{}'", details.display_name));
            return Err(format!("Cannot rename built-in group '{}'", details.display_name).into());
        }
        let schema = handler.get_schema().await?;
        let insert_attributes = group
            .insert_attributes
            .unwrap_or_default()
            .into_iter()
            .filter(|attr| attr.name != "displayname")
            .map(|attr| deserialize_attribute(schema.group_attributes(), attr, true))
            .collect::<Result<Vec<_>, _>>()?;
        handler
            .update_group(UpdateGroupRequest {
                group_id: GroupId(group.id),
                display_name: new_display_name.map(|s| s.as_str().into()),
                delete_attributes: group
                    .remove_attributes
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|attr| attr != "displayname")
                    .map(AttributeName::from)
                    .collect(),
                insert_attributes,
            })
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn add_user_to_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_to_group");
        span.in_scope(|| {
            debug!(?user_id, ?group_id);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized group membership modification",
            ))?;
        handler
            .add_user_to_group(&UserId::new(&user_id), GroupId(group_id))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn remove_user_from_group(
        context: &Context<Handler>,
        user_id: String,
        group_id: i32,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] remove_user_from_group");
        span.in_scope(|| {
            debug!(?user_id, ?group_id);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized group membership modification",
            ))?;
        let target_user_id = UserId::new(&user_id);
        let target_group_id = GroupId(group_id);
        let group_name = handler
            .get_group_details(target_group_id)
            .await
            .ok()
            .map(|d| d.display_name.to_string())
            .unwrap_or_default();
        if group_name == "lldap_admin" {
            if let Ok(members) = handler
                .list_users(Some(UserRequestFilter::MemberOfId(target_group_id)), false)
                .await
                && members.len() <= 1
            {
                span.in_scope(|| debug!("Cannot remove the last member of lldap_admin"));
                return Err("Cannot remove the last member of lldap_admin".into());
            }
            if context.validation_result.user == target_user_id {
                span.in_scope(|| debug!("Cannot remove admin rights for current user"));
                return Err("Cannot remove admin rights for current user".into());
            }
        }
        handler
            .remove_user_from_group(&target_user_id, target_group_id)
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_user(context: &Context<Handler>, user_id: String) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_user");
        span.in_scope(|| {
            debug!(?user_id);
        });
        let user_id_typed = UserId::new(&user_id);
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized user deletion"))?;
        if context.validation_result.user == user_id_typed {
            span.in_scope(|| debug!("Cannot delete current user"));
            return Err("Cannot delete current user".into());
        }
        handler.delete_user(&user_id_typed).instrument(span).await?;
        info!("Deleted user {user_id}");
        Ok(Success::new())
    }

    async fn delete_group(context: &Context<Handler>, group_id: i32) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_group");
        span.in_scope(|| {
            debug!(?group_id);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized group deletion"))?;
        if let Ok(details) = handler.get_group_details(GroupId(group_id)).await
            && is_protected_group(details.display_name.as_str(), context.mfa_policy)
        {
            span.in_scope(|| debug!("Cannot delete built-in group '{}'", details.display_name));
            return Err(format!("Cannot delete built-in group '{}'", details.display_name).into());
        }
        handler
            .delete_group(GroupId(group_id))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn create_ou(context: &Context<Handler>, name: String) -> FieldResult<Success> {
        ou::create_ou(context, name).await
    }

    async fn delete_ou(context: &Context<Handler>, name: String) -> FieldResult<Success> {
        ou::delete_ou(context, name).await
    }

    async fn change_user_ou(
        context: &Context<Handler>,
        user_ids: Vec<String>,
        new_ou: String,
    ) -> FieldResult<Success> {
        ou::change_user_ou(context, user_ids, new_ou).await
    }

    async fn change_group_ou(
        context: &Context<Handler>,
        group_ids: Vec<i32>,
        new_ou: String,
    ) -> FieldResult<Success> {
        ou::change_group_ou(context, group_ids, new_ou).await
    }

    async fn add_user_attribute(
        context: &Context<Handler>,
        name: String,
        attribute_type: GraphQLAttributeType,
        is_list: bool,
        is_visible: bool,
        is_editable: bool,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_attribute");
        span.in_scope(|| debug!(?name, ?attribute_type, is_list));
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute creation",
            ))?;
        let schema = handler.get_schema().await?;
        validate_new_attribute_name(&name, schema.group_attributes(), "group")?;
        handler
            .add_user_attribute(CreateAttributeRequest {
                name: name.into(),
                attribute_type: attribute_type.into(),
                is_list,
                is_visible,
                is_editable,
            })
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn add_group_attribute(
        context: &Context<Handler>,
        name: String,
        attribute_type: GraphQLAttributeType,
        is_list: bool,
        is_visible: bool,
        is_editable: bool,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_group_attribute");
        span.in_scope(|| debug!(?name, ?attribute_type, is_list));
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute creation",
            ))?;
        let schema = handler.get_schema().await?;
        validate_new_attribute_name(&name, schema.user_attributes(), "user")?;
        handler
            .add_group_attribute(CreateAttributeRequest {
                name: name.into(),
                attribute_type: attribute_type.into(),
                is_list,
                is_visible,
                is_editable,
            })
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_user_attribute(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_user_attribute");
        let name = AttributeName::from(name.as_str());
        span.in_scope(|| debug!(?name));
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute deletion",
            ))?;
        let schema = handler.get_schema().await?;
        let attribute_schema = schema
            .user_attributes()
            .get_by_name_or_alias(name.as_str())
            .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", name))?;
        if attribute_schema.is_hardcoded {
            return Err(anyhow!("Permission denied: Attribute {} cannot be deleted", name).into());
        }
        handler
            .delete_user_attribute(&name)
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_group_attribute(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_group_attribute");
        let name = AttributeName::from(name.as_str());
        span.in_scope(|| debug!(?name));
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized attribute deletion",
            ))?;
        let schema = handler.get_schema().await?;
        let attribute_schema = schema
            .group_attributes()
            .get_by_name_or_alias(name.as_str())
            .ok_or_else(|| anyhow!("Attribute {} is not defined in the schema", name))?;
        if attribute_schema.is_hardcoded {
            return Err(anyhow!("Permission denied: Attribute {} cannot be deleted", name).into());
        }
        handler
            .delete_group_attribute(&name)
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn add_user_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_user_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized object class addition",
            ))?;
        handler
            .add_user_object_class(&LdapObjectClass::from(name))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn add_group_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] add_group_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized object class addition",
            ))?;
        handler
            .add_group_object_class(&LdapObjectClass::from(name))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_user_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_user_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized object class deletion",
            ))?;
        handler
            .delete_user_object_class(&LdapObjectClass::from(name))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn delete_group_object_class(
        context: &Context<Handler>,
        name: String,
    ) -> FieldResult<Success> {
        let span = debug_span!("[GraphQL mutation] delete_group_object_class");
        span.in_scope(|| {
            debug!(?name);
        });
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized object class deletion",
            ))?;
        handler
            .delete_group_object_class(&LdapObjectClass::from(name))
            .instrument(span)
            .await?;
        Ok(Success::new())
    }

    async fn sync_kerberos_password(
        context: &Context<Handler>,
        user_id: String,
        encrypted_password: String,
    ) -> FieldResult<bool> {
        kerberos::sync_kerberos_password(context, user_id, encrypted_password).await
    }

    async fn export_keytab_for_keycloak(
        context: &Context<Handler>,
        hostname: String,
    ) -> FieldResult<ExportKeytabForKeycloakResponse> {
        kerberos::export_keytab_for_keycloak(context, hostname).await
    }

    async fn test_keycloak_connection(
        context: &Context<Handler>,
        input: TestKeycloakConnectionInput,
    ) -> FieldResult<TestKeycloakConnectionResponse> {
        keycloak::test_keycloak_connection(context, input).await
    }

    async fn save_keycloak_config(
        context: &Context<Handler>,
        input: SaveKeycloakConfigInput,
    ) -> FieldResult<SaveKeycloakConfigResponse> {
        keycloak::save_keycloak_config(context, input).await
    }

    async fn push_realm_to_keycloak(
        context: &Context<Handler>,
        input: PushRealmToKeycloakInput,
    ) -> FieldResult<PushRealmResponse> {
        keycloak::push_realm_to_keycloak(context, input).await
    }

    async fn set_posix_settings(
        context: &Context<Handler>,
        input: PosixSettingsInput,
    ) -> FieldResult<PosixSettingsResponse> {
        posix::set_posix_settings(context, input).await
    }

    async fn reassign_user_uid_numbers(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        posix::reassign_user_uid_numbers(context).await
    }

    async fn reassign_user_gid_numbers(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        posix::reassign_user_gid_numbers(context).await
    }

    async fn reassign_user_homedirectories(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        posix::reassign_user_homedirectories(context).await
    }

    async fn reassign_user_loginshells(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        posix::reassign_user_loginshells(context).await
    }

    async fn reassign_gid_numbers(
        context: &Context<Handler>,
    ) -> FieldResult<PosixSettingsResponse> {
        posix::reassign_gid_numbers(context).await
    }

    async fn reset_user_mfa(context: &Context<Handler>, user_id: String) -> FieldResult<Success> {
        mfa::reset_user_mfa(context, user_id).await
    }

    async fn reset_own_mfa(context: &Context<Handler>, code: String) -> FieldResult<Success> {
        mfa::reset_own_mfa(context, code).await
    }

    async fn start_mfa_enrollment(
        context: &Context<Handler>,
        current_code: Option<String>,
    ) -> FieldResult<MfaEnrollmentStart> {
        mfa::start_mfa_enrollment(context, current_code).await
    }

    async fn finish_mfa_enrollment(
        context: &Context<Handler>,
        state: String,
        code: String,
    ) -> FieldResult<Success> {
        mfa::finish_mfa_enrollment(context, state, code).await
    }
}
fn validate_new_attribute_name(
    name: &str,
    other_schema: &AttributeList,
    other_side: &str,
) -> FieldResult<()> {
    if other_schema.get_by_name_or_alias(name).is_some() {
        return Err(anyhow!(
            "Attribute '{}' already exists in the {} schema. Duplicate names are not allowed across user and group attributes.",
            name,
            other_side
        )
        .into());
    }
    validate_attribute_name(name).map_err(|invalid_chars: Vec<char>| -> FieldError {
        let chars = String::from_iter(invalid_chars);
        anyhow!(
            "Cannot create attribute with invalid name. Valid characters: {}. Invalid chars found: {}",
            ALLOWED_CHARACTERS_DESCRIPTION,
            chars
        )
        .into()
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Query;
    use juniper::{
        DefaultScalarValue, EmptySubscription, GraphQLType, InputValue, RootNode, Variables,
        execute, graphql_value,
    };
    use lldap_auth::access_control::{Permission, ValidationResults};
    use lldap_domain::types::{
        Attribute as DomainAttr, AttributeName, AttributeType,
        AttributeValue as DomainAttributeValue, Cardinality, Group, GroupDetails, GroupId,
        GroupName, User, UserAndGroups, Uuid,
    };
    use lldap_domain_handlers::mfa::MfaPolicy;
    use lldap_schema::{AttributeList, PublicSchema, Schema, schema::PosixSettings};
    use lldap_test_utils::MockTestBackendHandler;
    use lldap_test_utils::recording_kerberos::{KerberosOp, RecordingGuard};
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use serial_test::serial;

    fn mutation_schema<C, Q, M>(
        query_root: Q,
        mutation_root: M,
    ) -> RootNode<Q, M, EmptySubscription<C>>
    where
        Q: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()> + 'static,
        M: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()> + 'static,
    {
        RootNode::new(query_root, mutation_root, EmptySubscription::<C>::new())
    }

    fn make_test_schema() -> PublicSchema {
        PublicSchema(Schema {
            user_attributes: AttributeList { attributes: vec![] },
            group_attributes: AttributeList { attributes: vec![] },
            system_attributes: AttributeList { attributes: vec![] },
            posix_settings: PosixSettings::default(),
            extra_user_object_classes: vec![],
            extra_group_object_classes: vec![],
        })
    }

    #[tokio::test]
    async fn test_create_user_attribute_valid() {
        const QUERY: &str = r#"
            mutation CreateUserAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) {
                addUserAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) {
                    ok
                }
            }
        "#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema()
            .returning(|| Ok(make_test_schema()));
        mock.expect_add_user_attribute()
            .with(eq(CreateAttributeRequest {
                name: AttributeName::new("AttrName0"),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: false,
                is_editable: false,
            }))
            .return_once(|_| Ok(()));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::default(),
        );
        assert_eq!(
            execute(QUERY, None, &schema, &vars, &context).await,
            Ok((
                graphql_value!(
                {
                    "addUserAttribute": {
                        "ok": true
                    }
                } ),
                vec![]
            ))
        );
    }

    #[tokio::test]
    async fn test_create_user_attribute_invalid() {
        const QUERY: &str = r#"
            mutation CreateUserAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) {
                addUserAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) {
                    ok
                }
            }
        "#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema()
            .returning(|| Ok(make_test_schema()));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName_0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::default(),
        );
        let result = execute(QUERY, None, &schema, &vars, &context).await;
        match result {
            Ok(res) => {
                let (response, errors) = res;
                assert!(response.is_null());
                let expected_error_msg =
                    "Cannot create attribute with invalid name. Valid characters: a-z, A-Z, 0-9, and dash (-). Invalid chars found: _"
                        .to_string();
                assert!(
                    errors
                        .iter()
                        .all(|e| e.error().message() == expected_error_msg)
                );
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[tokio::test]
    async fn test_create_group_attribute_valid() {
        const QUERY: &str = r#"
            mutation CreateGroupAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!) {
                addGroupAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: false) {
                    ok
                }
            }
        "#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema()
            .returning(|| Ok(make_test_schema()));
        mock.expect_add_group_attribute()
            .with(eq(CreateAttributeRequest {
                name: AttributeName::new("AttrName0"),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: false,
                is_editable: false,
            }))
            .return_once(|_| Ok(()));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::default(),
        );
        assert_eq!(
            execute(QUERY, None, &schema, &vars, &context).await,
            Ok((
                graphql_value!(
                {
                    "addGroupAttribute": {
                        "ok": true
                    }
                } ),
                vec![]
            ))
        );
    }

    #[tokio::test]
    async fn test_create_group_attribute_invalid() {
        const QUERY: &str = r#"
            mutation CreateGroupAttribute($name: String!, $attributeType: AttributeType!, $isList: Boolean!, $isVisible: Boolean!, $isEditable: Boolean!) {
                addGroupAttribute(name: $name, attributeType: $attributeType, isList: $isList, isVisible: $isVisible, isEditable: $isEditable) {
                ok
            }
        }
    "#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema()
            .returning(|| Ok(make_test_schema()));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Admin,
            },
        );
        let vars = Variables::from([
            ("name".to_string(), InputValue::scalar("AttrName_0")),
            (
                "attributeType".to_string(),
                InputValue::enum_value("STRING"),
            ),
            ("isList".to_string(), InputValue::scalar(false)),
            ("isVisible".to_string(), InputValue::scalar(false)),
            ("isEditable".to_string(), InputValue::scalar(false)),
        ]);
        let schema = mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::default(),
        );
        let result = execute(QUERY, None, &schema, &vars, &context).await;
        match result {
            Ok(res) => {
                let (response, errors) = res;
                assert!(response.is_null());
                let expected_error_msg =
                "Cannot create attribute with invalid name. Valid characters: a-z, A-Z, 0-9, and dash (-). Invalid chars found: _"
                    .to_string();
                assert!(
                    errors
                        .iter()
                        .all(|e| e.error().message() == expected_error_msg)
                );
            }
            Err(_) => {
                panic!();
            }
        }
    }

    #[tokio::test]
    async fn test_attribute_consolidation_attr_precedence() {
        let attributes = vec![
            AttributeValue {
                name: "first_name".to_string(),
                value: vec!["expected-first".to_string()],
            },
            AttributeValue {
                name: "last_name".to_string(),
                value: vec!["expected-last".to_string()],
            },
            AttributeValue {
                name: "avatar".to_string(),
                value: vec!["expected-avatar".to_string()],
            },
        ];
        let schema = make_test_schema();
        let res = consolidate_attributes(
            attributes.clone(),
            Some("overridden-first".to_string()),
            Some("overridden-last".to_string()),
            Some("overriden-avatar".to_string()),
            &schema,
        );
        assert_eq!(
            res,
            vec![
                AttributeValue {
                    name: "avatar".to_string(),
                    value: vec!["expected-avatar".to_string()],
                },
                AttributeValue {
                    name: "first_name".to_string(),
                    value: vec!["expected-first".to_string()],
                },
                AttributeValue {
                    name: "last_name".to_string(),
                    value: vec!["expected-last".to_string()],
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_attribute_consolidation_field_fallback() {
        let attributes = Vec::new();
        let schema = make_test_schema();
        let res = consolidate_attributes(
            attributes.clone(),
            Some("expected-first".to_string()),
            Some("expected-last".to_string()),
            Some("expected-avatar".to_string()),
            &schema,
        );
        assert_eq!(
            res,
            vec![
                AttributeValue {
                    name: "avatar".to_string(),
                    value: vec!["expected-avatar".to_string()],
                },
                AttributeValue {
                    name: "first_name".to_string(),
                    value: vec!["expected-first".to_string()],
                },
                AttributeValue {
                    name: "last_name".to_string(),
                    value: vec!["expected-last".to_string()],
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_attribute_consolidation_field_fallback_2() {
        let attributes = vec![AttributeValue {
            name: "First_Name".to_string(),
            value: vec!["expected-first".to_string()],
        }];
        let schema = make_test_schema();
        let res = consolidate_attributes(
            attributes.clone(),
            Some("overriden-first".to_string()),
            Some("expected-last".to_string()),
            Some("expected-avatar".to_string()),
            &schema,
        );
        assert_eq!(
            res,
            vec![
                AttributeValue {
                    name: "avatar".to_string(),
                    value: vec!["expected-avatar".to_string()],
                },
                AttributeValue {
                    name: "first_name".to_string(),
                    value: vec!["expected-first".to_string()],
                },
                AttributeValue {
                    name: "last_name".to_string(),
                    value: vec!["expected-last".to_string()],
                },
            ]
        );
    }

    fn epoch() -> chrono::NaiveDateTime {
        chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc()
    }

    fn sample_user(id: &str, attributes: Vec<DomainAttr>) -> User {
        User {
            user_id: UserId::new(id),
            email: Email::from(format!("{id}@example.com")),
            display_name: None,
            creation_date: epoch(),
            uuid: Uuid::from_name_and_date(id, &epoch()),
            attributes,
            modified_date: epoch(),
            password_modified_date: epoch(),
            krb_principal_name: None,
            mfa_type: None,
        }
    }

    fn admin_context(mock: MockTestBackendHandler) -> Context<MockTestBackendHandler> {
        Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("admin"),
                permission: Permission::Admin,
            },
        )
    }

    fn regular_context(mock: MockTestBackendHandler) -> Context<MockTestBackendHandler> {
        Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Regular,
            },
        )
    }

    fn ou_attr(ou: &str) -> DomainAttr {
        DomainAttr {
            name: AttributeName::from("ou"),
            value: DomainAttributeValue::String(Cardinality::Singleton(ou.to_string())),
        }
    }

    fn has_ou(attributes: &[DomainAttr], ou: &str) -> bool {
        attributes.iter().any(|a| {
            a.name.as_str() == "ou"
                && a.value == DomainAttributeValue::String(Cardinality::Singleton(ou.to_string()))
        })
    }

    fn root_schema() -> RootNode<
        Query<MockTestBackendHandler>,
        Mutation<MockTestBackendHandler>,
        EmptySubscription<Context<MockTestBackendHandler>>,
    > {
        mutation_schema(
            Query::<MockTestBackendHandler>::new(),
            Mutation::<MockTestBackendHandler>::default(),
        )
    }

    fn assert_unauthorized(errors: &[juniper::ExecutionError<DefaultScalarValue>], query: &str) {
        assert!(
            errors
                .iter()
                .any(|e| e.error().message().contains("Unauthorized")),
            "expected an authorization error for {query}, got {errors:?}"
        );
    }

    fn posix_settings_mutation(uid_start: u32, uid_max: u32) -> String {
        format!(
            r#"mutation {{
                setPosixSettings(input: {{
                    userUidnumberAssign: true,
                    userUidnumberStart: {uid_start},
                    userUidnumberMax: {uid_max},
                    userGidnumberAssign: false,
                    userGidnumberStart: 3000,
                    userLoginshellAssign: false,
                    userLoginshellDefault: "",
                    userHomedirectoryAssign: false,
                    userHomedirectoryPrefix: "",
                    groupGidnumberAssign: false,
                    groupGidnumberStart: 3000,
                    groupGidnumberMax: 3000
                }}) {{ success }}
            }}"#
        )
    }

    // The lldap-cli argument shapes: `createGroup(name:)` against `createGroup(group:)`,
    // `users(where:)` against the legacy `users(filters:)`.
    #[tokio::test]
    async fn test_graphql_argument_forms() {
        for query in [
            r#"mutation { createGroup { id } }"#,
            r#"mutation {
                createGroup(name: "a", group: { displayName: "a" }) { id }
            }"#,
        ] {
            let context = admin_context(MockTestBackendHandler::new());
            let (_, errors) = execute(query, None, &root_schema(), &Variables::new(), &context)
                .await
                .unwrap();
            assert_eq!(errors.len(), 1, "expected one-of error for {query}");
            assert!(
                errors[0]
                    .error()
                    .message()
                    .contains("exactly one of `name` and `group`"),
                "unexpected error for {query}: {errors:?}"
            );
        }
        for query in [
            r#"query Q($f: RequestFilter) { users(filters: $f) { id } }"#,
            r#"query { users { id } }"#,
        ] {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_get_schema()
                .returning(|| Ok(make_test_schema()));
            mock.expect_list_users()
                .with(eq(None), eq(true))
                .return_once(|_, _| {
                    Ok(vec![UserAndGroups {
                        user: sample_user("bob", vec![]),
                        groups: None,
                    }])
                });
            let context = admin_context(mock);
            let (value, errors) = execute(query, None, &root_schema(), &Variables::new(), &context)
                .await
                .unwrap();
            assert_eq!(errors.len(), 0, "unexpected errors for {query}: {errors:?}");
            assert_eq!(value, graphql_value!({"users": [{"id": "bob"}]}), "{query}");
        }
        let context = admin_context(MockTestBackendHandler::new());
        let (_, errors) = execute(
            r#"query { users(where: {}, filters: {}) { id } }"#,
            None,
            &root_schema(),
            &Variables::new(),
            &context,
        )
        .await
        .unwrap();
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0]
                .error()
                .message()
                .contains("only one of `where` and `filters`"),
            "unexpected error: {errors:?}"
        );
    }

    // createOu, changeUserOu, changeGroupOu and deleteOu on one backend; each OU mutation
    // reads the OU list once, so the second read already sees the new OU.
    #[tokio::test]
    async fn test_ou_lifecycle_persists() {
        let mut mock = MockTestBackendHandler::new();
        let ou_lookups = std::sync::atomic::AtomicUsize::new(0);
        mock.expect_get_allowed_ous().returning(move || {
            let mut ous = vec!["people".to_string(), "groups".to_string()];
            if ou_lookups.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                ous.push("labs".to_string());
            }
            Ok(ous)
        });
        mock.expect_set_system_config()
            .withf(|k, v| k == "allowedous" && v.contains("labs"))
            .times(1)
            .returning(|_, _| Ok(()));
        mock.expect_update_user()
            .withf(|req| {
                req.user_id == UserId::new("bob") && has_ou(&req.insert_attributes, "labs")
            })
            .times(1)
            .returning(|_| Ok(()));
        mock.expect_update_group()
            .withf(|req| req.group_id == GroupId(7) && has_ou(&req.insert_attributes, "labs"))
            .times(1)
            .returning(|_| Ok(()));
        mock.expect_list_users().returning(|_, _| {
            Ok(vec![UserAndGroups {
                user: sample_user("bob", vec![ou_attr("labs")]),
                groups: None,
            }])
        });
        mock.expect_update_user()
            .withf(|req| {
                req.user_id == UserId::new("bob") && has_ou(&req.insert_attributes, "people")
            })
            .times(1)
            .returning(|_| Ok(()));
        mock.expect_list_groups().returning(|_| {
            Ok(vec![Group {
                id: GroupId(7),
                display_name: GroupName::from("builders"),
                creation_date: epoch(),
                uuid: Uuid::from_name_and_date("builders", &epoch()),
                users: vec![],
                attributes: vec![ou_attr("labs")],
                modified_date: epoch(),
            }])
        });
        mock.expect_update_group()
            .withf(|req| req.group_id == GroupId(7) && has_ou(&req.insert_attributes, "groups"))
            .times(1)
            .returning(|_| Ok(()));
        mock.expect_set_system_config()
            .withf(|k, v| k == "allowedous" && !v.contains("labs"))
            .times(1)
            .returning(|_, _| Ok(()));
        let context = admin_context(mock);
        for (query, expected) in [
            (
                r#"mutation { createOu(name: "labs") { ok } }"#,
                graphql_value!({"createOu": {"ok": true}}),
            ),
            (
                r#"mutation { changeUserOu(userIds: ["bob"], newOu: "labs") { ok } }"#,
                graphql_value!({"changeUserOu": {"ok": true}}),
            ),
            (
                r#"mutation { changeGroupOu(groupIds: [7], newOu: "labs") { ok } }"#,
                graphql_value!({"changeGroupOu": {"ok": true}}),
            ),
            (
                r#"mutation { deleteOu(name: "labs") { ok } }"#,
                graphql_value!({"deleteOu": {"ok": true}}),
            ),
        ] {
            let (value, errors) = execute(query, None, &root_schema(), &Variables::new(), &context)
                .await
                .unwrap();
            assert_eq!(errors.len(), 0, "{query}: {errors:?}");
            assert_eq!(value, expected, "{query}");
        }
    }

    #[tokio::test]
    async fn test_set_posix_settings_range() {
        let context = admin_context(MockTestBackendHandler::new());
        let (_, errors) = execute(
            &posix_settings_mutation(1, 2),
            None,
            &root_schema(),
            &Variables::new(),
            &context,
        )
        .await
        .unwrap();
        assert!(
            errors.iter().any(|e| e
                .error()
                .message()
                .contains("must be between 3000 and 60000")),
            "expected a range error, got {errors:?}"
        );

        let mut mock = MockTestBackendHandler::new();
        mock.expect_set_posix_settings()
            .times(1)
            .returning(|_| Ok(()));
        let context = admin_context(mock);
        let (value, errors) = execute(
            &posix_settings_mutation(3000, 4000),
            None,
            &root_schema(),
            &Variables::new(),
            &context,
        )
        .await
        .unwrap();
        assert_eq!(errors.len(), 0, "{errors:?}");
        assert_eq!(
            value,
            graphql_value!({"setPosixSettings": {"success": true}})
        );
    }

    #[tokio::test]
    async fn test_ou_and_posix_mutations_require_admin() {
        let posix_settings = posix_settings_mutation(3000, 4000);
        for query in [
            r#"mutation { createOu(name: "labs") { ok } }"#,
            r#"mutation { deleteOu(name: "labs") { ok } }"#,
            r#"mutation { changeUserOu(userIds: ["bob"], newOu: "labs") { ok } }"#,
            r#"mutation { changeGroupOu(groupIds: [1], newOu: "labs") { ok } }"#,
            posix_settings.as_str(),
            r#"mutation { reassignUserUidNumbers { success } }"#,
            r#"mutation { reassignUserGidNumbers { success } }"#,
            r#"mutation { reassignUserHomedirectories { success } }"#,
            r#"mutation { reassignUserLoginshells { success } }"#,
            r#"mutation { reassignGidNumbers { success } }"#,
        ] {
            let context = regular_context(MockTestBackendHandler::new());
            let (_, errors) = execute(query, None, &root_schema(), &Variables::new(), &context)
                .await
                .unwrap();
            assert_unauthorized(&errors, query);
        }
    }

    async fn posix_reassign_ok(
        query: &str,
        field: &str,
        setup: impl FnOnce(&mut MockTestBackendHandler),
    ) {
        let mut mock = MockTestBackendHandler::new();
        setup(&mut mock);
        let context = admin_context(mock);
        let (value, errors) = execute(query, None, &root_schema(), &Variables::new(), &context)
            .await
            .unwrap();
        assert_eq!(errors.len(), 0, "{errors:?}");
        let inner = value
            .as_object_value()
            .and_then(|o| o.get_field_value(field))
            .expect(field);
        assert_eq!(inner, &graphql_value!({ "success": true }));
    }

    #[tokio::test]
    async fn test_posix_reassign_mutations_delegate() {
        posix_reassign_ok(
            r#"mutation { reassignUserUidNumbers { success } }"#,
            "reassignUserUidNumbers",
            |m| {
                m.expect_reassign_user_uid_numbers()
                    .times(1)
                    .returning(|| Ok(()));
            },
        )
        .await;
        posix_reassign_ok(
            r#"mutation { reassignUserGidNumbers { success } }"#,
            "reassignUserGidNumbers",
            |m| {
                m.expect_reassign_user_gid_numbers()
                    .times(1)
                    .returning(|| Ok(()));
            },
        )
        .await;
        posix_reassign_ok(
            r#"mutation { reassignUserHomedirectories { success } }"#,
            "reassignUserHomedirectories",
            |m| {
                m.expect_reassign_user_homedirectories()
                    .times(1)
                    .returning(|| Ok(()));
            },
        )
        .await;
        posix_reassign_ok(
            r#"mutation { reassignUserLoginshells { success } }"#,
            "reassignUserLoginshells",
            |m| {
                m.expect_reassign_user_loginshells()
                    .times(1)
                    .returning(|| Ok(()));
            },
        )
        .await;
        posix_reassign_ok(
            r#"mutation { reassignGidNumbers { success } }"#,
            "reassignGidNumbers",
            |m| {
                m.expect_reassign_gid_numbers()
                    .times(1)
                    .returning(|| Ok(()));
            },
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_export_keytab_goes_through_the_seam() {
        const QUERY: &str = r#"
            mutation {
                exportKeytabForKeycloak(hostname: "kc.example.com") {
                    ok
                    path
                }
            }
        "#;
        let guard = RecordingGuard::install();
        let context = admin_context(MockTestBackendHandler::new());
        let (value, errors) = execute(QUERY, None, &root_schema(), &Variables::new(), &context)
            .await
            .unwrap();
        assert_eq!(errors.len(), 0, "{errors:?}");
        assert_eq!(
            value,
            graphql_value!({
                "exportKeytabForKeycloak": {
                    "ok": true,
                    "path": "/tmp/recording.keytab"
                }
            })
        );
        assert_eq!(
            guard.recorder().take_ops(),
            vec![KerberosOp::ExportKeytab {
                hostname: "kc.example.com".into(),
            }]
        );
    }

    fn password_manager_context(mock: MockTestBackendHandler) -> Context<MockTestBackendHandler> {
        Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("pm"),
                permission: Permission::PasswordManager,
            },
        )
    }

    fn policy_context(
        mock: MockTestBackendHandler,
        user: &str,
        permission: Permission,
        policy: MfaPolicy,
        pending: bool,
    ) -> Context<MockTestBackendHandler> {
        Context::<MockTestBackendHandler>::new_for_tests_with_policy(
            mock,
            ValidationResults {
                user: UserId::new(user),
                permission,
            },
            policy,
            pending,
        )
    }

    fn group_set(name: &str) -> std::collections::HashSet<GroupDetails> {
        std::collections::HashSet::from([GroupDetails {
            group_id: GroupId(1),
            display_name: name.into(),
            creation_date: epoch(),
            uuid: Uuid::from_name_and_date(name, &epoch()),
            attributes: vec![],
            modified_date: epoch(),
        }])
    }

    fn enrollment_start() -> lldap_domain::types::TotpEnrollmentStart {
        lldap_domain::types::TotpEnrollmentStart {
            otpauth_uri: "otpauth://totp/KLLDAP:bob?secret=ABC".to_owned(),
            secret_base32: "ABC".to_owned(),
            state: "sealed".to_owned(),
        }
    }

    fn user_var(user: &str) -> Variables {
        Variables::from([("u".to_string(), InputValue::scalar(user))])
    }

    const RESET_USER_MFA: &str = r#"mutation($u: String!) { resetUserMfa(userId: $u) { ok } }"#;
    const START_MFA: &str = r#"mutation { startMfaEnrollment { otpauthUri secretBase32 state } }"#;
    const FINISH_MFA: &str =
        r#"mutation { finishMfaEnrollment(state: "sealed", code: "123456") { ok } }"#;
    const RESET_OWN_MFA: &str = r#"mutation { resetOwnMfa(code: "123456") { ok } }"#;

    fn expect_mfa_reset(mock: &mut MockTestBackendHandler, user: &str) {
        let expected = UserId::new(user);
        mock.expect_get_user_groups()
            .with(eq(expected.clone()))
            .returning(|_| Ok(std::collections::HashSet::new()));
        mock.expect_reset_user_mfa()
            .with(
                eq(expected),
                eq(lldap_domain_handlers::mfa::MfaResetReason::Administrative),
            )
            .times(1)
            .returning(|_, _| Ok(()));
    }

    #[tokio::test]
    async fn test_reset_user_mfa_authorization() {
        let mut mock = MockTestBackendHandler::new();
        expect_mfa_reset(&mut mock, "bob");
        let (value, errors) = execute(
            RESET_USER_MFA,
            None,
            &root_schema(),
            &user_var("bob"),
            &admin_context(mock),
        )
        .await
        .unwrap();
        assert_eq!(errors.len(), 0, "{errors:?}");
        assert_eq!(value, graphql_value!({"resetUserMfa": {"ok": true}}));

        let mut mock = MockTestBackendHandler::new();
        expect_mfa_reset(&mut mock, "bob");
        let (value, errors) = execute(
            RESET_USER_MFA,
            None,
            &root_schema(),
            &user_var("bob"),
            &password_manager_context(mock),
        )
        .await
        .unwrap();
        assert_eq!(errors.len(), 0, "{errors:?}");
        assert_eq!(value, graphql_value!({"resetUserMfa": {"ok": true}}));

        // A password manager can touch neither an admin's factor nor their own.
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("alice")))
            .returning(|_| Ok(group_set("lldap_admin")));
        let (_, errors) = execute(
            RESET_USER_MFA,
            None,
            &root_schema(),
            &user_var("alice"),
            &password_manager_context(mock),
        )
        .await
        .unwrap();
        assert_unauthorized(&errors, RESET_USER_MFA);
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("pm")))
            .returning(|_| Ok(std::collections::HashSet::new()));
        let (_, errors) = execute(
            RESET_USER_MFA,
            None,
            &root_schema(),
            &user_var("pm"),
            &password_manager_context(mock),
        )
        .await
        .unwrap();
        assert_unauthorized(&errors, RESET_USER_MFA);

        // Regular users never can, not even for themselves.
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .returning(|_| Ok(std::collections::HashSet::new()));
        let (_, errors) = execute(
            RESET_USER_MFA,
            None,
            &root_schema(),
            &user_var("bob"),
            &regular_context(mock),
        )
        .await
        .unwrap();
        assert_unauthorized(&errors, RESET_USER_MFA);
        let (_, errors) = execute(
            RESET_USER_MFA,
            None,
            &root_schema(),
            &user_var("alice"),
            &regular_context(MockTestBackendHandler::new()),
        )
        .await
        .unwrap();
        assert_unauthorized(&errors, RESET_USER_MFA);

        // Under "always" an admin cannot reset their own factor, whatever the id's case.
        let context = policy_context(
            MockTestBackendHandler::new(),
            "bob",
            Permission::Admin,
            MfaPolicy::Always,
            false,
        );
        let (_, errors) = execute(
            RESET_USER_MFA,
            None,
            &root_schema(),
            &user_var("Bob"),
            &context,
        )
        .await
        .unwrap();
        assert!(
            errors
                .iter()
                .any(|e| e.error().message().contains("Cannot reset your own MFA")),
            "{errors:?}"
        );
    }

    #[tokio::test]
    async fn test_mfa_mutation_policy_gates() {
        for query in [START_MFA, FINISH_MFA, RESET_OWN_MFA] {
            let (_, errors) = execute(
                query,
                None,
                &root_schema(),
                &Variables::new(),
                &regular_context(MockTestBackendHandler::new()),
            )
            .await
            .unwrap();
            assert!(
                errors
                    .iter()
                    .any(|e| e.error().message().contains("MFA is disabled")),
                "{query}: {errors:?}"
            );
        }
        // The administrative reset stays available as the cleanup path.
        let mut mock = MockTestBackendHandler::new();
        expect_mfa_reset(&mut mock, "bob");
        let (value, errors) = execute(
            RESET_USER_MFA,
            None,
            &root_schema(),
            &user_var("bob"),
            &admin_context(mock),
        )
        .await
        .unwrap();
        assert_eq!(errors.len(), 0, "{errors:?}");
        assert_eq!(value, graphql_value!({"resetUserMfa": {"ok": true}}));

        let mut mock = MockTestBackendHandler::new();
        mock.expect_start_totp_enrollment()
            .with(eq(UserId::new("bob")), eq(None::<String>))
            .times(1)
            .returning(|_, _| Ok(enrollment_start()));
        mock.expect_finish_totp_enrollment()
            .withf(|user, state, code| {
                user == &UserId::new("bob") && state == "sealed" && code == "123456"
            })
            .times(1)
            .returning(|_, _, _| Ok(()));
        mock.expect_reset_own_mfa()
            .withf(|user, code| user == &UserId::new("bob") && code == "123456")
            .times(1)
            .returning(|_, _| Ok(()));
        let context = policy_context(mock, "bob", Permission::Regular, MfaPolicy::Enrolled, false);
        for (query, expected) in [
            (
                START_MFA,
                graphql_value!({"startMfaEnrollment": {
                    "otpauthUri": "otpauth://totp/KLLDAP:bob?secret=ABC",
                    "secretBase32": "ABC",
                    "state": "sealed",
                }}),
            ),
            (
                FINISH_MFA,
                graphql_value!({"finishMfaEnrollment": {"ok": true}}),
            ),
            (RESET_OWN_MFA, graphql_value!({"resetOwnMfa": {"ok": true}})),
        ] {
            let (value, errors) = execute(query, None, &root_schema(), &Variables::new(), &context)
                .await
                .unwrap();
            assert_eq!(errors.len(), 0, "{query}: {errors:?}");
            assert_eq!(value, expected, "{query}");
        }

        let context = policy_context(
            MockTestBackendHandler::new(),
            "bob",
            Permission::Regular,
            MfaPolicy::Always,
            false,
        );
        let (_, errors) = execute(
            RESET_OWN_MFA,
            None,
            &root_schema(),
            &Variables::new(),
            &context,
        )
        .await
        .unwrap();
        assert!(
            errors.iter().any(|e| e
                .error()
                .message()
                .contains("MFA is required by the server configuration")),
            "{errors:?}"
        );
    }

    #[tokio::test]
    async fn test_mutations_gated_until_enrolled_under_always() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema()
            .returning(|| Ok(make_test_schema()));
        mock.expect_get_user_details()
            .with(eq(UserId::new("admin")))
            .returning(|_| Ok(sample_user("admin", vec![])));
        mock.expect_start_totp_enrollment()
            .returning(|_, _| Ok(enrollment_start()));
        let context = policy_context(mock, "admin", Permission::Admin, MfaPolicy::Always, true);
        for query in [
            r#"{ users { id } }"#,
            r#"{ schema { userSchema { attributes { name } } } }"#,
            r#"mutation { updateUser(user: {id: "bob"}) { ok } }"#,
        ] {
            let (_, errors) = execute(query, None, &root_schema(), &Variables::new(), &context)
                .await
                .unwrap();
            assert_unauthorized(&errors, query);
        }
        let (value, errors) = execute(
            r#"{ user(userId: "admin") { id } }"#,
            None,
            &root_schema(),
            &Variables::new(),
            &context,
        )
        .await
        .unwrap();
        assert_eq!(errors.len(), 0, "{errors:?}");
        assert_eq!(value, graphql_value!({"user": {"id": "admin"}}));
        let (_, errors) = execute(START_MFA, None, &root_schema(), &Variables::new(), &context)
            .await
            .unwrap();
        assert_eq!(errors.len(), 0, "{errors:?}");
        let (_, errors) = execute(
            RESET_USER_MFA,
            None,
            &root_schema(),
            &user_var("bob"),
            &context,
        )
        .await
        .unwrap();
        assert_unauthorized(&errors, RESET_USER_MFA);
    }
}
