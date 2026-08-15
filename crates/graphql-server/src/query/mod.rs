pub mod attribute;
pub mod filters;
pub mod group;
pub mod schema;
pub mod user;

pub use attribute::{
    AttributeSchema, AttributeValue, GraphQLAttributeType, serialize_attribute_to_graphql,
};
pub use filters::{EqualityConstraint, RequestFilter};
pub use group::Group;
pub use schema::{AttributeList, ObjectClassInfo, Schema};
pub use user::User;

use crate::api::FullHandler;
use crate::api::{Context, field_error_callback};
use juniper::GraphQLObject;
use juniper::{FieldError, FieldResult, graphql_object, graphql_value};
use lldap_access_control::{ReadonlyBackendHandler, UserReadableBackendHandler};
use lldap_domain::types::{GroupId, UserId};
use lldap_domain_handlers::handler::{
    BackendHandler, PosixBackendHandler, ReadSchemaBackendHandler, SystemConfigBackendHandler,
};
use lldap_keycloak::{KeycloakConfig, SUGGESTED_HOSTNAME};
use lldap_opaque_handler::OpaqueHandler;
use lldap_schema::PublicSchema;
use std::sync::Arc;
use tracing::{Instrument, Span, debug, debug_span};

#[derive(PartialEq, Eq, Debug)]
/// The top-level GraphQL query type.
pub struct Query<Handler: FullHandler + OpaqueHandler> {
    _phantom: std::marker::PhantomData<Box<Handler>>,
}

#[derive(GraphQLObject)]
pub struct KerberosInfo {
    pub public_key_der_base64: Option<String>,
}

#[derive(GraphQLObject)]
pub struct KeycloakSuggestedConfig {
    pub url: String,
    pub realm: String,
    #[graphql(name = "adminUsername")]
    pub admin_username: String,
    #[graphql(name = "keycloakHostname")]
    pub keycloak_hostname: String,
}

#[derive(GraphQLObject)]
pub struct KeycloakConfigResponse {
    pub url: String,
    pub realm: String,
    #[graphql(name = "adminUser")]
    pub admin_user: String,
}

#[derive(GraphQLObject, Default)]
pub struct PosixSettings {
    // === Users ===
    pub user_uidnumber_assign: bool,
    pub user_uidnumber_start: i32,
    pub user_uidnumber_max: i32,

    pub user_gidnumber_assign: bool,
    pub user_gidnumber_start: i32,

    pub user_loginshell_assign: bool,
    pub user_loginshell_default: String,

    pub user_homedirectory_assign: bool,
    pub user_homedirectory_prefix: String,

    // === Groups ===
    pub group_gidnumber_assign: bool,
    pub group_gidnumber_start: i32,
    pub group_gidnumber_max: i32,
}

impl<Handler: BackendHandler + OpaqueHandler> Default for Query<Handler> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Handler: BackendHandler + OpaqueHandler> Query<Handler> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

#[graphql_object(context = Context<Handler>)]
impl<Handler: FullHandler + OpaqueHandler> Query<Handler> {
    fn api_version() -> &'static str {
        "1.0"
    }

    pub async fn user(
        &self,
        context: &Context<Handler>,
        user_id: String,
    ) -> FieldResult<User<Handler>> {
        use anyhow::Context;
        let span = debug_span!("[GraphQL query] user");
        span.in_scope(|| {
            debug!(?user_id);
        });
        let user_id = urlencoding::decode(&user_id).context("Invalid user parameter")?;
        let user_id = UserId::new(&user_id);
        let handler =
            context
                .get_readable_handler(user_id.clone())
                .ok_or_else(field_error_callback(
                    &span,
                    "Unauthorized access to user data",
                ))?;
        let schema = Arc::new(self.get_schema(context, span.clone()).await?);
        let user = handler.get_user_details(&user_id).instrument(span).await?;
        User::<Handler>::from_user(user, schema)
    }

    async fn users(
        &self,
        context: &Context<Handler>,
        #[graphql(name = "where")] where_filters: Option<RequestFilter>,
        filters: Option<RequestFilter>,
    ) -> FieldResult<Vec<User<Handler>>> {
        let span = debug_span!("[GraphQL query] users");
        span.in_scope(|| {
            debug!(?where_filters, ?filters);
        });
        let filters = match (where_filters, filters) {
            (Some(_), Some(_)) => {
                return Err(field_error_callback(
                    &span,
                    "users accepts only one of `where` and `filters`",
                )());
            }
            (w, f) => w.or(f),
        };
        let handler = context
            .get_readonly_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to user list",
            ))?;
        let schema = Arc::new(self.get_schema(context, span.clone()).await?);
        let users = handler
            .list_users(
                filters
                    .map(|f| f.try_into_domain_filter(&schema))
                    .transpose()?,
                true,
            )
            .instrument(span)
            .await?;
        users
            .into_iter()
            .map(|u| User::<Handler>::from_user_and_groups(u, schema.clone()))
            .collect()
    }

    async fn groups(&self, context: &Context<Handler>) -> FieldResult<Vec<Group<Handler>>> {
        let span = debug_span!("[GraphQL query] groups");
        let handler = context
            .get_readonly_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to group list",
            ))?;
        let schema = Arc::new(self.get_schema(context, span.clone()).await?);
        let domain_groups = handler.list_groups(None).instrument(span).await?;
        domain_groups
            .into_iter()
            .map(|g| Group::<Handler>::from_group(g, schema.clone()))
            .collect()
    }

    async fn group(
        &self,
        context: &Context<Handler>,
        group_id: i32,
    ) -> FieldResult<Group<Handler>> {
        let span = debug_span!("[GraphQL query] group");
        span.in_scope(|| {
            debug!(?group_id);
        });
        let handler = context
            .get_readonly_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized access to group data",
            ))?;
        let schema = Arc::new(self.get_schema(context, span.clone()).await?);
        let group_details = handler
            .get_group_details(GroupId(group_id))
            .instrument(span)
            .await?;
        Group::<Handler>::from_group_details(group_details, schema.clone())
    }

    async fn schema(&self, context: &Context<Handler>) -> FieldResult<Schema<Handler>> {
        let span = debug_span!("[GraphQL query] get_schema");
        self.get_schema(context, span).await.map(Into::into)
    }

    fn kerberos_info(&self, _context: &Context<Handler>) -> FieldResult<KerberosInfo> {
        Ok(KerberosInfo {
            public_key_der_base64: Some(crate::kerberos_transport::public_key_der_base64()),
        })
    }

    async fn keycloak_suggested_config(
        context: &Context<Handler>,
    ) -> FieldResult<KeycloakSuggestedConfig> {
        let span = debug_span!("[GraphQL query] keycloak_suggested_config");
        context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized to read Keycloak config",
            ))?;

        let cfg = KeycloakConfig::suggested();
        Ok(KeycloakSuggestedConfig {
            url: cfg.url,
            realm: cfg.realm,
            admin_username: cfg.admin_user,
            keycloak_hostname: SUGGESTED_HOSTNAME.to_owned(),
        })
    }

    async fn keycloak_config(context: &Context<Handler>) -> FieldResult<KeycloakConfigResponse> {
        let span = debug_span!("[GraphQL query] keycloak_config");
        context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized to read Keycloak config",
            ))?;

        let cfg = KeycloakConfig::load().map_err(|e| {
            FieldError::new(
                format!("Could not read the Keycloak config: {e:#}"),
                juniper::Value::null(),
            )
        })?;

        Ok(KeycloakConfigResponse {
            url: cfg.url,
            realm: cfg.realm,
            admin_user: cfg.admin_user,
        })
    }

    async fn list_ous(context: &Context<Handler>) -> FieldResult<Vec<String>> {
        let span = debug_span!("[GraphQL query] list_ous");
        span.in_scope(|| debug!("Fetching global allowedous list (single source of truth)"));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized to read OUs"))?;

        let ous = handler.get_allowed_ous().await.map_err(|e| {
            FieldError::new(
                "Failed to load allowedous",
                graphql_value!({ "details": (e.to_string()) }),
            )
        })?;

        Ok(ous)
    }

    async fn posix_settings(context: &Context<Handler>) -> FieldResult<PosixSettings> {
        let span = debug_span!("[GraphQL query] posix_settings");
        span.in_scope(|| debug!("Fetching full POSIX settings (single source of truth)"));

        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized to read POSIX settings",
            ))?;

        let settings = handler.get_posix_settings().await.map_err(|e| {
            FieldError::new(
                "Failed to load posix_settings",
                graphql_value!({ "details": (e.to_string()) }),
            )
        })?;

        Ok(PosixSettings {
            user_uidnumber_assign: settings.user_uidnumber_assign,
            user_uidnumber_start: settings.user_uidnumber_start as i32,
            user_uidnumber_max: settings.user_uidnumber_max as i32,
            user_gidnumber_assign: settings.user_gidnumber_assign,
            user_gidnumber_start: settings.user_gidnumber_start as i32,
            user_loginshell_assign: settings.user_loginshell_assign,
            user_loginshell_default: settings.user_loginshell_default,
            user_homedirectory_assign: settings.user_homedirectory_assign,
            user_homedirectory_prefix: settings.user_homedirectory_prefix,
            group_gidnumber_assign: settings.group_gidnumber_assign,
            group_gidnumber_start: settings.group_gidnumber_start as i32,
            group_gidnumber_max: settings.group_gidnumber_max as i32,
        })
    }
}

impl<Handler: BackendHandler + OpaqueHandler> Query<Handler> {
    async fn get_schema(
        &self,
        context: &Context<Handler>,
        span: Span,
    ) -> FieldResult<PublicSchema> {
        let handler = context
            .handler
            .get_user_restricted_lister_handler(&context.validation_result);
        Ok(handler.get_schema().instrument(span).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use juniper::{
        DefaultScalarValue, EmptyMutation, EmptySubscription, GraphQLType, RootNode, Variables,
        execute, graphql_value,
    };
    use lldap_auth::access_control::{Permission, ValidationResults};
    use lldap_domain::types::{Attribute as DomainAttribute, GroupDetails, User as DomainUser};
    use lldap_domain::types::{AttributeName, AttributeType};
    use lldap_domain_model::model::UserColumn;
    use lldap_schema::{
        AttributeList, AttributeSchema as DomainAttributeSchema,
        PosixSettings as DomainPosixSettings, Schema,
    };
    use lldap_test_utils::{MockTestBackendHandler, setup_default_schema};
    use mockall::predicate::eq;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn schema<C, Q>(query_root: Q) -> RootNode<Q, EmptyMutation<C>, EmptySubscription<C>>
    where
        Q: GraphQLType<DefaultScalarValue, Context = C, TypeInfo = ()>,
    {
        RootNode::new(
            query_root,
            EmptyMutation::<C>::new(),
            EmptySubscription::<C>::new(),
        )
    }

    #[tokio::test]
    async fn get_user_by_id() {
        const QUERY: &str = r#"{
            user(userId: "bob") {
                id
                email
                creationDate
                firstName
                lastName
                uuid
                attributes {
                    value
                }
                groups {
                    id
                    displayName
                    creationDate
                    uuid
                    attributes {
                        value
                    }
                }
            }
        }"#;

        let mut mock = MockTestBackendHandler::new();
        mock.expect_get_schema().returning(|| {
            Ok(PublicSchema(Schema {
                user_attributes: AttributeList {
                    attributes: vec![
                        DomainAttributeSchema {
                            name: "first_name".into(),
                            aliases: vec![],
                            attribute_type: AttributeType::String,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                            is_readonly: false,
                        },
                        DomainAttributeSchema {
                            name: "last_name".into(),
                            aliases: vec![],
                            attribute_type: AttributeType::String,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                            is_readonly: false,
                        },
                    ],
                },
                group_attributes: AttributeList {
                    attributes: vec![DomainAttributeSchema {
                        name: "club_name".into(),
                        aliases: vec![],
                        attribute_type: AttributeType::String,
                        is_list: false,
                        is_visible: true,
                        is_editable: true,
                        is_hardcoded: false,
                        is_readonly: false,
                    }],
                },
                system_attributes: AttributeList { attributes: vec![] },
                posix_settings: DomainPosixSettings::default(),
                extra_user_object_classes: vec![
                    "customUserClass".to_string(),
                    "myUserClass".to_string(),
                ],
                extra_group_object_classes: vec!["customGroupClass".to_string()],
            }))
        });
        mock.expect_get_user_details()
            .with(eq(UserId::new("bob")))
            .return_once(|_| {
                Ok(DomainUser {
                    user_id: UserId::new("bob"),
                    email: "bob@bobbers.on".into(),
                    display_name: None,
                    creation_date: chrono::Utc.timestamp_millis_opt(42).unwrap().naive_utc(),
                    modified_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                    password_modified_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                    uuid: lldap_domain::types::Uuid::from_name_and_date(
                        "bob",
                        &chrono::Utc.timestamp_millis_opt(42).unwrap().naive_utc(),
                    ),
                    attributes: vec![
                        DomainAttribute {
                            name: "first_name".into(),
                            value: "Bob".to_string().into(),
                        },
                        DomainAttribute {
                            name: "last_name".into(),
                            value: "Bobberson".to_string().into(),
                        },
                    ],
                    krb_principal_name: None,
                })
            });
        let mut groups = HashSet::new();
        groups.insert(GroupDetails {
            group_id: GroupId(3),
            display_name: "Bobbersons".into(),
            creation_date: chrono::Utc.timestamp_nanos(42).naive_utc(),
            uuid: lldap_domain::types::Uuid::from_name_and_date(
                "Bobbersons",
                &chrono::Utc.timestamp_nanos(42).naive_utc(),
            ),
            attributes: vec![DomainAttribute {
                name: "club_name".into(),
                value: "Gang of Four".to_string().into(),
            }],
            modified_date: chrono::Utc.timestamp_nanos(42).naive_utc(),
        });
        groups.insert(GroupDetails {
            group_id: GroupId(7),
            display_name: "Jefferees".into(),
            creation_date: chrono::Utc.timestamp_nanos(12).naive_utc(),
            uuid: lldap_domain::types::Uuid::from_name_and_date(
                "Jefferees",
                &chrono::Utc.timestamp_nanos(12).naive_utc(),
            ),
            attributes: Vec::new(),
            modified_date: chrono::Utc.timestamp_nanos(12).naive_utc(),
        });
        mock.expect_get_user_groups()
            .with(eq(UserId::new("bob")))
            .return_once(|_| Ok(groups));

        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("admin"),
                permission: Permission::Admin,
            },
        );

        let schema = schema(Query::<MockTestBackendHandler>::new());
        let result = execute(QUERY, None, &schema, &Variables::new(), &context).await;
        assert!(result.is_ok(), "Query failed: {:?}", result);
    }

    #[tokio::test]
    async fn list_users() {
        const QUERY: &str = r#"{
        users(where: {
            any: [
                {eq: { field: "id", value: "bob" }},
                {eq: { field: "email", value: "robert@bobbers.on" }},
                {eq: { field: "firstName", value: "robert" }}
            ]
        }) {
            id
            email
        }
    }"#;

        let mut mock = MockTestBackendHandler::new();
        setup_default_schema(&mut mock);
        mock.expect_list_users()
            .with(
                eq(Some(lldap_domain_handlers::handler::UserRequestFilter::Or(
                    vec![
                        lldap_domain_handlers::handler::UserRequestFilter::UserId(UserId::new(
                            "bob",
                        )),
                        lldap_domain_handlers::handler::UserRequestFilter::Equality(
                            UserColumn::Email,
                            "robert@bobbers.on".to_owned(),
                        ),
                        lldap_domain_handlers::handler::UserRequestFilter::AttributeEquality(
                            AttributeName::from("firstname"),
                            "robert".to_string().into(),
                        ),
                    ],
                ))),
                eq(true),
            )
            .return_once(|_, _| {
                Ok(vec![
                    lldap_domain::types::UserAndGroups {
                        user: DomainUser {
                            user_id: UserId::new("bob"),
                            email: "bob@bobbers.on".into(),
                            display_name: None,
                            creation_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                            modified_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                            password_modified_date: chrono::Utc
                                .timestamp_opt(0, 0)
                                .unwrap()
                                .naive_utc(),
                            uuid: lldap_domain::types::Uuid::from_name_and_date(
                                "bob",
                                &chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                            ),
                            attributes: Vec::new(),
                            krb_principal_name: None,
                        },
                        groups: None,
                    },
                    lldap_domain::types::UserAndGroups {
                        user: DomainUser {
                            user_id: UserId::new("robert"),
                            email: "robert@bobbers.on".into(),
                            display_name: None,
                            creation_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                            modified_date: chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                            password_modified_date: chrono::Utc
                                .timestamp_opt(0, 0)
                                .unwrap()
                                .naive_utc(),
                            uuid: lldap_domain::types::Uuid::from_name_and_date(
                                "robert",
                                &chrono::Utc.timestamp_opt(0, 0).unwrap().naive_utc(),
                            ),
                            attributes: Vec::new(),
                            krb_principal_name: None,
                        },
                        groups: None,
                    },
                ])
            });

        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("admin"),
                permission: Permission::Admin,
            },
        );

        let schema = schema(Query::<MockTestBackendHandler>::new());
        assert_eq!(
            execute(QUERY, None, &schema, &Variables::new(), &context).await,
            Ok((
                graphql_value!({
                    "users": [
                        { "id": "bob", "email": "bob@bobbers.on" },
                        { "id": "robert", "email": "robert@bobbers.on" }
                    ]
                }),
                vec![]
            ))
        );
    }

    #[tokio::test]
    async fn get_schema() {
        const QUERY: &str = r#"{
            schema {
                userSchema {
                    attributes {
                        name
                        attributeType
                        isList
                        isVisible
                        isEditable
                        isHardcoded
                    }
                    extraLdapObjectClasses
                }
                groupSchema {
                    attributes {
                        name
                        attributeType
                        isList
                        isVisible
                        isEditable
                        isHardcoded
                    }
                    extraLdapObjectClasses
                }
            }
        }"#;

        let mut mock = MockTestBackendHandler::new();
        setup_default_schema(&mut mock);

        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("admin"),
                permission: Permission::Admin,
            },
        );

        let schema = schema(Query::<MockTestBackendHandler>::new());
        let result = execute(QUERY, None, &schema, &Variables::new(), &context).await;
        assert!(result.is_ok(), "Query failed: {:?}", result);
    }

    #[tokio::test]
    async fn regular_user_doesnt_see_non_visible_attributes() {
        const QUERY: &str = r#"{
            schema {
                userSchema {
                    attributes { name }
                    extraLdapObjectClasses
                }
            }
        }"#;

        let mut mock = MockTestBackendHandler::new();

        mock.expect_get_schema().times(1).return_once(|| {
            Ok(PublicSchema(Schema {
                user_attributes: AttributeList {
                    attributes: vec![DomainAttributeSchema {
                        name: "invisible".into(),
                        aliases: vec![],
                        attribute_type: AttributeType::Avatar,
                        is_list: false,
                        is_visible: false,
                        is_editable: true,
                        is_hardcoded: true,
                        is_readonly: false,
                    }],
                },
                group_attributes: AttributeList {
                    attributes: Vec::new(),
                },
                system_attributes: AttributeList { attributes: vec![] },
                posix_settings: DomainPosixSettings::default(),
                extra_user_object_classes: vec!["customUserClass".to_string()],
                extra_group_object_classes: vec![],
            }))
        });

        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("bob"),
                permission: Permission::Regular,
            },
        );

        let schema = schema(Query::<MockTestBackendHandler>::new());
        let result = execute(QUERY, None, &schema, &Variables::new(), &context).await;
        assert!(result.is_ok(), "Query failed: {:?}", result);
    }
}
