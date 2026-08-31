pub mod attribute;
pub mod filters;
pub mod group;
pub mod logs;
pub mod policy;
pub mod schema;
pub mod user;

pub use attribute::{
    AttributeSchema, AttributeValue, GraphQLAttributeType, serialize_attribute_to_graphql,
};
pub use filters::{EqualityConstraint, RequestFilter};
pub use group::Group;
pub use logs::{
    GraphQLLogDimension, GraphQLLogKind, GraphQLLogProtocol, LogActivity, LogBucket, LogEntry,
    LogFilterInput,
};
pub use schema::{AttributeList, ObjectClassInfo, Schema};
pub use user::User;

use crate::api::{Context, FullHandler, field_error_callback};
use crate::kerberos_transport::public_key_der_base64;
use anyhow::anyhow;
use juniper::{FieldResult, GraphQLObject, ID, graphql_object};
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
    pub user_uidnumber_assign: bool,
    pub user_uidnumber_start: i32,
    pub user_uidnumber_max: i32,
    pub user_gidnumber_assign: bool,
    pub user_gidnumber_start: i32,
    pub user_loginshell_assign: bool,
    pub user_loginshell_default: String,
    pub user_homedirectory_assign: bool,
    pub user_homedirectory_prefix: String,
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
                return Err("users accepts only one of `where` and `filters`".into());
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
        if context.mfa_enrollment_pending {
            span.in_scope(|| debug!("Unauthorized schema read"));
            return Err("Unauthorized schema read".into());
        }
        self.get_schema(context, span).await.map(Into::into)
    }

    fn kerberos_info(&self, _context: &Context<Handler>) -> FieldResult<KerberosInfo> {
        Ok(KerberosInfo {
            public_key_der_base64: Some(public_key_der_base64()),
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
        let cfg = KeycloakConfig::load()
            .map_err(|e| anyhow!("Could not read the Keycloak config: {e:#}"))?;
        Ok(KeycloakConfigResponse {
            url: cfg.url,
            realm: cfg.realm,
            admin_user: cfg.admin_user,
        })
    }

    async fn list_ous(context: &Context<Handler>) -> FieldResult<Vec<String>> {
        let span = debug_span!("[GraphQL query] list_ous");
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(&span, "Unauthorized to read OUs"))?;
        Ok(handler
            .get_allowed_ous()
            .await
            .map_err(|e| anyhow!("Failed to load allowedous: {e}"))?)
    }

    async fn policies(context: &Context<Handler>) -> FieldResult<Vec<policy::GraphQLPolicy>> {
        policy::policies(context).await
    }

    async fn policy(
        context: &Context<Handler>,
        policy_id: i32,
    ) -> FieldResult<policy::GraphQLPolicy> {
        policy::policy(context, policy_id).await
    }

    async fn policy_item_catalog(
        context: &Context<Handler>,
    ) -> FieldResult<Vec<policy::GraphQLPolicyCatalogItem>> {
        policy::policy_item_catalog(context)
    }

    async fn effective_policy_items(
        context: &Context<Handler>,
        ou: String,
    ) -> FieldResult<Vec<policy::GraphQLEffectivePolicyItem>> {
        policy::effective_policy_items(context, ou).await
    }

    async fn ou_policy_states(
        context: &Context<Handler>,
    ) -> FieldResult<Vec<policy::GraphQLOuPolicyState>> {
        policy::ou_policy_states(context).await
    }

    async fn posix_settings(context: &Context<Handler>) -> FieldResult<PosixSettings> {
        let span = debug_span!("[GraphQL query] posix_settings");
        let handler = context
            .get_admin_handler()
            .ok_or_else(field_error_callback(
                &span,
                "Unauthorized to read POSIX settings",
            ))?;
        let settings = handler
            .get_posix_settings()
            .await
            .map_err(|e| anyhow!("Failed to load posix_settings: {e}"))?;
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

    /// Newest first; `beforeId` pages back, `afterId` pages forward oldest first.
    async fn logs(
        context: &Context<Handler>,
        filter: Option<LogFilterInput>,
        limit: Option<i32>,
        before_id: Option<ID>,
        after_id: Option<ID>,
    ) -> FieldResult<Vec<LogEntry>> {
        logs::list_logs(context, filter, limit, before_id, after_id).await
    }

    /// Counts per distinct combination of `groupBy`, most frequent first; no `groupBy` gives
    /// the total.
    async fn log_summary(
        context: &Context<Handler>,
        filter: Option<LogFilterInput>,
        group_by: Option<Vec<GraphQLLogDimension>>,
        limit: Option<i32>,
    ) -> FieldResult<Vec<LogBucket>> {
        logs::log_summary(context, filter, group_by, limit).await
    }

    /// One user's last success and failure among `kinds` (default: bind and login) and the
    /// failures since that success.
    async fn log_activity(
        context: &Context<Handler>,
        actor: String,
        kinds: Option<Vec<GraphQLLogKind>>,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> FieldResult<LogActivity> {
        logs::log_activity(context, actor, kinds, since).await
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
    use lldap_domain_handlers::logging::{
        LOGIN_KINDS, LogActivity as DomainLogActivity, LogBucket as DomainLogBucket, LogCursor,
        LogDimension, LogEvent, LogFilter, LogKind, LogRecord, Protocol,
    };
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
                    mfa_type: None,
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
                            mfa_type: None,
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
                            mfa_type: None,
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

    fn log_record(id: i64, kind: LogKind, actor: &str) -> LogRecord {
        LogRecord {
            id,
            event: LogEvent {
                timestamp: chrono::Utc
                    .timestamp_opt(1714564800 + id, 0)
                    .unwrap()
                    .naive_utc(),
                kind,
                success: kind != LogKind::AccessDenied,
                protocol: Protocol::Ldap,
                actor: Some(actor.to_owned()),
                target: None,
                peer: Some("10.0.0.5".to_owned()),
                forwarded_for: None,
                detail: (kind == LogKind::AccessDenied).then(|| "Unauthorized write".to_owned()),
            },
        }
    }

    #[tokio::test]
    async fn test_logs_requires_admin() {
        const QUERIES: [&str; 3] = [
            r#"{ logs(limit: 5) { id } }"#,
            r#"{ logSummary(groupBy: [ACTOR]) { count } }"#,
            r#"{ logActivity(actor: "bob") { failuresSinceLastSuccess } }"#,
        ];
        for permission in [
            Permission::Regular,
            Permission::PasswordManager,
            Permission::Readonly,
        ] {
            for query in QUERIES {
                let mut mock = MockTestBackendHandler::new();
                mock.expect_list_log_events().times(0);
                mock.expect_summarize_log_events().times(0);
                mock.expect_log_activity().times(0);
                let context = Context::<MockTestBackendHandler>::new_for_tests(
                    mock,
                    ValidationResults {
                        user: UserId::new("bob"),
                        permission,
                    },
                );
                let schema = schema(Query::<MockTestBackendHandler>::new());
                let (_, errors) = execute(query, None, &schema, &Variables::new(), &context)
                    .await
                    .unwrap();
                assert!(
                    errors.iter().any(|e| e
                        .error()
                        .message()
                        .contains("Unauthorized to read the logs")),
                    "{permission:?} {query}: {errors:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_policy_queries_require_admin() {
        const QUERIES: [&str; 5] = [
            r#"{ policies { id } }"#,
            r#"{ policy(policyId: 1) { id } }"#,
            r#"{ policyItemCatalog { key } }"#,
            r#"{ effectivePolicyItems(ou: "") { key } }"#,
            r#"{ ouPolicyStates { ou } }"#,
        ];
        for query in QUERIES {
            let mut mock = MockTestBackendHandler::new();
            mock.expect_list_policies().times(0);
            mock.expect_get_policy().times(0);
            mock.expect_get_policy_levels().times(0);
            mock.expect_list_ou_policy_states().times(0);
            let context = Context::<MockTestBackendHandler>::new_for_tests(
                mock,
                ValidationResults {
                    user: UserId::new("bob"),
                    permission: Permission::Regular,
                },
            );
            let schema = schema(Query::<MockTestBackendHandler>::new());
            let (_, errors) = execute(query, None, &schema, &Variables::new(), &context)
                .await
                .unwrap();
            assert!(
                errors
                    .iter()
                    .any(|e| e.error().message().contains("Unauthorized")),
                "{query}: {errors:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_logs_maps_filter_pagination_and_rows() {
        const QUERY: &str = r#"{
        logs(filter: {kinds: [BIND], success: false, actor: "Bob", protocol: LDAP,
                      since: "2024-05-01T00:00:00Z"}, limit: 50, beforeId: "41") {
            id
            timestamp
            kind
            success
            protocol
            actor
            target
            peer
            forwardedFor
            detail
        }
    }"#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_log_events()
            .withf(|filter, limit, cursor| {
                *filter
                    == LogFilter {
                        actor: Some(UserId::new("bob")),
                        kinds: vec![LogKind::Bind],
                        success: Some(false),
                        protocol: Some(Protocol::Ldap),
                        since: Some(
                            chrono::Utc
                                .timestamp_opt(1714521600, 0)
                                .unwrap()
                                .naive_utc(),
                        ),
                        ..Default::default()
                    }
                    && *limit == 50
                    && *cursor == LogCursor::Before(41)
            })
            .times(1)
            .return_once(|_, _, _| {
                Ok(vec![
                    log_record(40, LogKind::AccessDenied, "bob"),
                    log_record(12, LogKind::Bind, "bob"),
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
                    "logs": [
                        {
                            "id": "40",
                            "timestamp": "2024-05-01T12:00:40Z",
                            "kind": "ACCESS_DENIED",
                            "success": false,
                            "protocol": "LDAP",
                            "actor": "bob",
                            "target": None,
                            "peer": "10.0.0.5",
                            "forwardedFor": None,
                            "detail": "Unauthorized write",
                        },
                        {
                            "id": "12",
                            "timestamp": "2024-05-01T12:00:12Z",
                            "kind": "BIND",
                            "success": true,
                            "protocol": "LDAP",
                            "actor": "bob",
                            "target": None,
                            "peer": "10.0.0.5",
                            "forwardedFor": None,
                            "detail": None,
                        },
                    ]
                }),
                vec![]
            ))
        );
    }
    #[tokio::test]
    async fn test_logs_cursors_and_defaults() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_list_log_events()
            .withf(|filter, limit, cursor| {
                *filter == LogFilter::default() && *limit == 100 && *cursor == LogCursor::Newest
            })
            .times(1)
            .return_once(|_, _, _| Ok(vec![]));
        mock.expect_list_log_events()
            .withf(|filter, limit, cursor| {
                *filter
                    == LogFilter {
                        member_of: Some("Devs".to_owned()),
                        member_of_id: Some(GroupId(3)),
                        ..Default::default()
                    }
                    && *limit == 1000
                    && *cursor == LogCursor::After(41)
            })
            .times(1)
            .return_once(|_, _, _| Ok(vec![log_record(42, LogKind::Bind, "bob")]));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("admin"),
                permission: Permission::Admin,
            },
        );
        let schema = schema(Query::<MockTestBackendHandler>::new());
        for (label, query, expected) in [
            (
                "defaults",
                r#"{ logs { id } }"#,
                graphql_value!({ "logs": [] }),
            ),
            (
                "after cursor, limit clamped",
                r#"{ logs(filter: {memberOf: "Devs", memberOfId: 3}, limit: 5000, afterId: "41") { id } }"#,
                graphql_value!({ "logs": [{ "id": "42" }] }),
            ),
        ] {
            assert_eq!(
                execute(query, None, &schema, &Variables::new(), &context).await,
                Ok((expected, vec![])),
                "{label}"
            );
        }
        for (label, query, message) in [
            (
                "bad cursor",
                r#"{ logs(beforeId: "not-a-number") { id } }"#,
                "Invalid log id",
            ),
            (
                "cursor conflict",
                r#"{ logs(beforeId: "41", afterId: "12") { id } }"#,
                "logs takes either beforeId or afterId",
            ),
        ] {
            let (_, errors) = execute(query, None, &schema, &Variables::new(), &context)
                .await
                .unwrap();
            assert!(
                errors.iter().any(|e| e.error().message().contains(message)),
                "{label}: {errors:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_log_summary_maps_filter_group_by_and_buckets() {
        const QUERY: &str = r#"{
        logSummary(filter: {kinds: [BIND, LOGIN], success: false, memberOfId: 7,
                            since: "2024-05-01T00:00:00Z"},
                   groupBy: [ACTOR, DAY], limit: 5) {
            actor
            target
            kind
            protocol
            peer
            success
            day
            hour
            count
            first
            last
        }
    }"#;
        let mut mock = MockTestBackendHandler::new();
        mock.expect_summarize_log_events()
            .withf(|filter, group_by, limit| {
                *filter
                    == LogFilter {
                        kinds: vec![LogKind::Bind, LogKind::Login],
                        success: Some(false),
                        member_of_id: Some(GroupId(7)),
                        since: Some(
                            chrono::Utc
                                .timestamp_opt(1714521600, 0)
                                .unwrap()
                                .naive_utc(),
                        ),
                        ..Default::default()
                    }
                    && *group_by == vec![LogDimension::Actor, LogDimension::Day]
                    && *limit == 5
            })
            .times(1)
            .return_once(|_, _, _| {
                let at = |secs: i64| {
                    chrono::Utc
                        .timestamp_opt(1714564800 + secs, 0)
                        .unwrap()
                        .naive_utc()
                };
                Ok(vec![
                    DomainLogBucket {
                        actor: Some("bob".to_owned()),
                        target: None,
                        kind: None,
                        protocol: None,
                        peer: None,
                        success: None,
                        day: Some("2024-05-01".to_owned()),
                        hour: None,
                        count: 3,
                        first: at(0),
                        last: at(120),
                    },
                    DomainLogBucket {
                        actor: None,
                        target: None,
                        kind: Some(LogKind::Bind),
                        protocol: Some(Protocol::Ldap),
                        peer: Some("10.0.0.5".to_owned()),
                        success: Some(false),
                        day: None,
                        hour: Some(23),
                        count: 1,
                        first: at(5),
                        last: at(5),
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
                    "logSummary": [
                        {
                            "actor": "bob",
                            "target": None,
                            "kind": None,
                            "protocol": None,
                            "peer": None,
                            "success": None,
                            "day": "2024-05-01",
                            "hour": None,
                            "count": 3,
                            "first": "2024-05-01T12:00:00Z",
                            "last": "2024-05-01T12:02:00Z",
                        },
                        {
                            "actor": None,
                            "target": None,
                            "kind": "BIND",
                            "protocol": "LDAP",
                            "peer": "10.0.0.5",
                            "success": false,
                            "day": None,
                            "hour": 23,
                            "count": 1,
                            "first": "2024-05-01T12:00:05Z",
                            "last": "2024-05-01T12:00:05Z",
                        },
                    ]
                }),
                vec![]
            ))
        );

        let mut mock = MockTestBackendHandler::new();
        mock.expect_summarize_log_events()
            .withf(|filter, group_by, limit| {
                *filter == LogFilter::default() && group_by.is_empty() && *limit == 100
            })
            .times(1)
            .return_once(|_, _, _| Ok(vec![]));
        let context = Context::<MockTestBackendHandler>::new_for_tests(
            mock,
            ValidationResults {
                user: UserId::new("admin"),
                permission: Permission::Admin,
            },
        );
        assert_eq!(
            execute(
                r#"{ logSummary { count } }"#,
                None,
                &schema,
                &Variables::new(),
                &context
            )
            .await,
            Ok((graphql_value!({ "logSummary": [] }), vec![]))
        );
    }

    #[tokio::test]
    async fn test_log_activity_maps_defaults_and_records() {
        let mut mock = MockTestBackendHandler::new();
        mock.expect_log_activity()
            .withf(|actor, kinds, since| {
                actor == &UserId::new("bob") && *kinds == LOGIN_KINDS && since.is_none()
            })
            .times(1)
            .return_once(|actor, _, _| {
                Ok(DomainLogActivity {
                    actor: actor.clone(),
                    last_success: None,
                    last_failure: Some(log_record(40, LogKind::AccessDenied, "bob")),
                    failures_since_last_success: 4,
                })
            });
        mock.expect_log_activity()
            .withf(|actor, kinds, since| {
                actor == &UserId::new("carol")
                    && *kinds == vec![LogKind::Login, LogKind::TokenRefresh]
                    && *since
                        == Some(
                            chrono::Utc
                                .timestamp_opt(1714521600, 0)
                                .unwrap()
                                .naive_utc(),
                        )
            })
            .times(1)
            .return_once(|actor, _, _| {
                Ok(DomainLogActivity {
                    actor: actor.clone(),
                    last_success: Some(log_record(12, LogKind::Login, "carol")),
                    last_failure: None,
                    failures_since_last_success: 0,
                })
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
            execute(
                r#"{
                bob: logActivity(actor: "Bob") {
                    actor
                    lastSuccess { id }
                    lastFailure { id kind detail }
                    failuresSinceLastSuccess
                }
                carol: logActivity(actor: "carol", kinds: [LOGIN, TOKEN_REFRESH],
                                   since: "2024-05-01T00:00:00Z") {
                    actor
                    lastSuccess { id timestamp }
                    lastFailure { id }
                    failuresSinceLastSuccess
                }
            }"#,
                None,
                &schema,
                &Variables::new(),
                &context
            )
            .await,
            Ok((
                graphql_value!({
                    "bob": {
                        "actor": "bob",
                        "lastSuccess": None,
                        "lastFailure": {
                            "id": "40",
                            "kind": "ACCESS_DENIED",
                            "detail": "Unauthorized write",
                        },
                        "failuresSinceLastSuccess": 4,
                    },
                    "carol": {
                        "actor": "carol",
                        "lastSuccess": {
                            "id": "12",
                            "timestamp": "2024-05-01T12:00:12Z",
                        },
                        "lastFailure": None,
                        "failuresSinceLastSuccess": 0,
                    },
                }),
                vec![]
            ))
        );
    }
}
