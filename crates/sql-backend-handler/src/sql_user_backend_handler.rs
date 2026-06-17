use crate::sql_backend_handler::SqlBackendHandler;
use async_trait::async_trait;
use itertools::Itertools;
use lldap_domain::{
    requests::{CreateUserRequest, UpdateUserRequest},
    types::{
        Attribute, AttributeName, AttributeValue, Cardinality, GroupDetails, GroupId, Serialized,
        User, UserAndGroups, UserId, Uuid,
    },
};
use lldap_domain_handlers::handler::{
    GroupBackendHandler, PosixBackendHandler, PosixSettings, ReadSchemaBackendHandler,
    SubStringFilter, SystemConfigBackendHandler, UserBackendHandler, UserListerBackendHandler,
    UserRequestFilter,
};
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, GroupColumn, UserColumn, deserialize, system_config},
};
use lldap_kerberos::delete_kerberos_principal;
use lldap_schema::PublicSchema;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseTransaction, EntityTrait, ModelTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set, TransactionTrait,
    sea_query::{
        Alias, Cond, Expr, Func, IntoColumnRef, IntoCondition, SimpleExpr, query::OnConflict,
    },
};
use std::collections::HashSet;
use tracing::{debug, instrument};

// Helper: Convert AttributeValue to raw bytes for the EAV value BLOB column
fn attribute_value_to_db_bytes(value: &AttributeValue) -> Vec<u8> {
    match value {
        AttributeValue::String(Cardinality::Singleton(s)) => s.as_bytes().to_vec(),
        AttributeValue::String(Cardinality::Unbounded(list)) => {
            serde_json::to_vec(list).unwrap_or_else(|_| b"[]".to_vec())
        }
        AttributeValue::Integer(Cardinality::Singleton(i)) => i.to_string().as_bytes().to_vec(),
        AttributeValue::Avatar(Cardinality::Singleton(p)) => p.0.clone(),
        AttributeValue::DateTime(Cardinality::Singleton(dt)) => {
            dt.and_utc().timestamp().to_string().as_bytes().to_vec()
        }
        _ => vec![],
    }
}

fn attribute_condition(name: AttributeName, value: Option<&AttributeValue>) -> Cond {
    Expr::in_subquery(
        Expr::col(UserColumn::UserId.as_column_ref()),
        model::UserAttributes::find()
            .select_only()
            .column(model::UserAttributesColumn::UserId)
            .filter(model::UserAttributesColumn::AttributeName.eq(name))
            .filter(
                value
                    .map(|v| model::UserAttributesColumn::Value.eq(attribute_value_to_db_bytes(v)))
                    .unwrap_or_else(|| SimpleExpr::Constant(true.into())),
            )
            .into_query(),
    )
    .into_condition()
}

fn attribute_substring_condition(name: AttributeName, filter: &SubStringFilter) -> Cond {
    let like_pattern = filter.to_sql_filter();
    Expr::in_subquery(
        Expr::col(UserColumn::UserId.as_column_ref()),
        model::UserAttributes::find()
            .select_only()
            .column(model::UserAttributesColumn::UserId)
            .filter(model::UserAttributesColumn::AttributeName.eq(name.clone()))
            .filter(
                SimpleExpr::FunctionCall(Func::lower(Expr::col(
                    model::UserAttributesColumn::Value,
                )))
                .like(like_pattern),
            )
            .into_query(),
    )
    .into_condition()
}

fn user_id_subcondition(filter: Cond) -> Cond {
    Expr::in_subquery(
        Expr::col(UserColumn::UserId.as_column_ref()),
        model::User::find()
            .find_also_linked(model::memberships::UserToGroup)
            .select_only()
            .column(UserColumn::UserId)
            .filter(filter)
            .into_query(),
    )
    .into_condition()
}

fn get_user_filter_expr(filter: UserRequestFilter) -> Cond {
    use UserRequestFilter::*;
    let group_table = Alias::new("r1");
    fn bool_to_expr(b: bool) -> Cond {
        SimpleExpr::Value(b.into()).into_condition()
    }
    fn get_repeated_filter(
        fs: Vec<UserRequestFilter>,
        condition: Cond,
        default_value: bool,
    ) -> Cond {
        if fs.is_empty() {
            bool_to_expr(default_value)
        } else {
            fs.into_iter()
                .map(get_user_filter_expr)
                .fold(condition, Cond::add)
        }
    }
    match filter {
        True => bool_to_expr(true),
        False => bool_to_expr(false),
        And(fs) => get_repeated_filter(fs, Cond::all(), true),
        Or(fs) => get_repeated_filter(fs, Cond::any(), false),
        Not(f) => get_user_filter_expr(*f).not(),
        UserId(user_id) => ColumnTrait::eq(&UserColumn::UserId, user_id).into_condition(),
        Equality(column, value) => {
            if column == UserColumn::UserId {
                panic!("User id should be wrapped")
            } else if column == UserColumn::Email {
                ColumnTrait::eq(&UserColumn::LowercaseEmail, value.as_str().to_lowercase())
                    .into_condition()
            } else {
                ColumnTrait::eq(&column, value).into_condition()
            }
        }
        AttributeEquality(column, value) => attribute_condition(column, Some(&value)),
        MemberOf(group) => user_id_subcondition(
            Expr::col((group_table, GroupColumn::LowercaseDisplayName))
                .eq(group.as_str().to_lowercase())
                .into_condition(),
        ),
        MemberOfId(group_id) => user_id_subcondition(
            Expr::col((group_table, GroupColumn::GroupId))
                .eq(group_id)
                .into_condition(),
        ),
        UserIdSubString(filter) => UserColumn::UserId
            .like(filter.to_sql_filter())
            .into_condition(),
        SubString(col, filter) => {
            SimpleExpr::FunctionCall(Func::lower(Expr::col(col.as_column_ref())))
                .like(filter.to_sql_filter())
                .into_condition()
        }
        CustomAttributePresent(name) => attribute_condition(name, None),

        // NEW: GreaterOrEqual / LessOrEqual for timestamps (user side) — closes #1308
        GreaterOrEqual(column, value) => match column {
            UserColumn::CreationDate
            | UserColumn::ModifiedDate
            | UserColumn::PasswordModifiedDate => ColumnTrait::gte(&column, value).into_condition(),
            _ => panic!("GreaterOrEqual only supported on date columns"),
        },
        LessOrEqual(column, value) => match column {
            UserColumn::CreationDate
            | UserColumn::ModifiedDate
            | UserColumn::PasswordModifiedDate => ColumnTrait::lte(&column, value).into_condition(),
            _ => panic!("LessOrEqual only supported on date columns"),
        },
        AttributeGreaterOrEqual(name, value) => Expr::in_subquery(
            Expr::col(GroupColumn::GroupId.as_column_ref()),
            model::GroupAttributes::find()
                .select_only()
                .column(model::GroupAttributesColumn::GroupId)
                .filter(model::GroupAttributesColumn::AttributeName.eq(name))
                .filter(model::GroupAttributesColumn::Value.gte(value))
                .into_query(),
        )
        .into_condition(),
        AttributeLessOrEqual(name, value) => Expr::in_subquery(
            Expr::col(GroupColumn::GroupId.as_column_ref()),
            model::GroupAttributes::find()
                .select_only()
                .column(model::GroupAttributesColumn::GroupId)
                .filter(model::GroupAttributesColumn::AttributeName.eq(name))
                .filter(model::GroupAttributesColumn::Value.lte(value))
                .into_query(),
        )
        .into_condition(),
        AttributeSubString(name, filter) => attribute_substring_condition(name, &filter),
    }
}

fn to_value(opt_name: &Option<String>) -> ActiveValue<Option<String>> {
    match opt_name {
        None => ActiveValue::NotSet,
        Some(name) => ActiveValue::Set(if name.is_empty() {
            None
        } else {
            Some(name.to_owned())
        }),
    }
}

fn is_backend_writable_readonly_attribute(name: &str) -> bool {
    matches!(
        name,
        "ou" | "kerberossync" | "allowedous" | "krb_principal_name"
    )
}

#[async_trait]
impl UserListerBackendHandler for SqlBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        _get_groups: bool,
    ) -> Result<Vec<UserAndGroups>> {
        let filters = filters
            .map(get_user_filter_expr)
            .unwrap_or_else(|| SimpleExpr::Value(true.into()).into_condition());

        let mut users: Vec<_> = model::User::find()
            .filter(filters.clone())
            .order_by_asc(UserColumn::UserId)
            .find_with_linked(model::memberships::UserToGroup)
            .order_by_asc(SimpleExpr::Column(
                (Alias::new("r1"), GroupColumn::DisplayName).into_column_ref(),
            ))
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(|(user, groups)| UserAndGroups {
                user: user.into(),
                groups: Some(groups.into_iter().map(Into::<GroupDetails>::into).collect()),
            })
            .collect();

        let attributes = model::UserAttributes::find()
            .filter(
                model::UserAttributesColumn::UserId.in_subquery(
                    model::User::find()
                        .filter(filters)
                        .select_only()
                        .column(model::users::Column::UserId)
                        .into_query(),
                ),
            )
            .order_by_asc(model::UserAttributesColumn::UserId)
            .order_by_asc(model::UserAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;

        let mut attributes_iter = attributes.into_iter().peekable();
        let schema = self.get_schema().await?;
        for user in users.iter_mut() {
            let mut attrs: Vec<_> = attributes_iter
                .take_while_ref(|u| u.user_id == user.user.user_id)
                .map(|a| {
                    deserialize::deserialize_attribute(
                        a.attribute_name,
                        &a.value,
                        schema.user_attributes(),
                    )
                })
                .collect::<Result<Vec<_>>>()?;

            // Defensive canonical remap on read path (matches get_user_details).
            // Ensures AttributeEquality filters and list output always use canonical names,
            // even if legacy alias data exists. Reuses the shared helper.
            for attr in &mut attrs {
                attr.name = Self::canonical_user_attribute_name(&schema, attr.name.as_str());
            }
            user.user.attributes = attrs;

            user.user.materialize_protected_fields();
        }
        Ok(users)
    }
}

impl SqlBackendHandler {
    fn compute_user_attribute_changes(
        user_id: &UserId,
        insert_attributes: Vec<Attribute>,
        delete_attributes: Vec<AttributeName>,
        schema: &PublicSchema,
    ) -> Result<(
        Vec<model::user_attributes::ActiveModel>,
        Vec<AttributeName>,
        Option<bool>,
    )> {
        let mut update_user_attributes = Vec::new();
        // Resolve delete names to canonical too (supports alias in delete requests + keeps storage invariant)
        let mut remove_user_attributes: Vec<AttributeName> = delete_attributes
            .into_iter()
            .map(|name| SqlBackendHandler::canonical_user_attribute_name(schema, name.as_str()))
            .collect();
        let mut kerb_sync_enabled: Option<bool> = None;

        for attribute in insert_attributes {
            let canonical_name = schema
                .user_attributes()
                .get_by_name_or_alias(attribute.name.as_str())
                .map(|s| s.name.clone().into())
                .unwrap_or_else(|| attribute.name.clone());

            if attribute.name.as_str() == "kerberossync" {
                kerb_sync_enabled = match &attribute.value {
                    // Frontend (user_details_form + kerberos_switch) sends String "0"/"1"
                    AttributeValue::String(Cardinality::Singleton(s)) => match s.trim() {
                        "1" | "true" | "TRUE" => Some(true),
                        "0" | "false" | "FALSE" => Some(false),
                        _ => Some(false),
                    },
                    // Support the old Integer style too (for safety)
                    AttributeValue::Integer(Cardinality::Singleton(1)) => Some(true),
                    AttributeValue::Integer(Cardinality::Singleton(0)) => Some(false),
                    _ => Some(false),
                };
            }

            // === BACKEND BYPASS FOR READONLY ATTRIBUTES USED BY OU OPERATIONS ===
            let attr_name = attribute.name.as_str();
            if schema
                .user_attributes()
                .get_attribute_type(attr_name)
                .is_some()
                || is_backend_writable_readonly_attribute(attr_name)
            {
                let db_value = attribute_value_to_db_bytes(&attribute.value);

                update_user_attributes.push(model::user_attributes::ActiveModel {
                    user_id: Set(user_id.clone()),
                    attribute_name: Set(canonical_name.clone()),
                    value: Set(Serialized(db_value)),
                });
            } else {
                return Err(DomainError::InternalError(format!(
                    "User attribute name {} doesn't exist in the schema",
                    attribute.name
                )));
            }
        }

        remove_user_attributes.retain(|name| {
            !update_user_attributes
                .iter()
                .any(|u| u.attribute_name == Set(name.clone()))
        });

        Ok((
            update_user_attributes,
            remove_user_attributes,
            kerb_sync_enabled,
        ))
    }

    async fn update_user_with_transaction(
        transaction: &DatabaseTransaction,
        request: UpdateUserRequest,
    ) -> Result<()> {
        let schema = Self::get_schema_with_transaction(transaction).await?;
        let (update_user_attributes, remove_user_attributes, kerb_sync_enabled) =
            Self::compute_user_attribute_changes(
                &request.user_id,
                request.insert_attributes,
                request.delete_attributes,
                &schema,
            )?;

        let lower_email = request.email.as_ref().map(|s| s.as_str().to_lowercase());
        let now = chrono::Utc::now().naive_utc();

        // === POSIX RANGE + DUPLICATE CHECKS (uidnumber on users; gidnumber uniqueness is group-only) ===
        let _settings = Self::get_posix_settings_with_transaction(transaction).await?;

        for attr in &update_user_attributes {
            let name = match &attr.attribute_name {
                ActiveValue::Set(n) => n.as_str(),
                _ => continue,
            };

            let value = match &attr.value {
                ActiveValue::Set(Serialized(bytes)) => match String::from_utf8(bytes.clone()) {
                    Ok(s) => s.trim().parse::<i64>().unwrap_or(0),
                    Err(_) => continue,
                },
                _ => continue,
            };

            if name == "uidnumber" || name == "gidnumber" {
                if !(3000..=60000).contains(&value) {
                    return Err(DomainError::InternalError(format!(
                        "{} must be between 3000 and 60000",
                        name
                    )));
                }

                if name == "uidnumber" {
                    if Self::is_uidnumber_taken(transaction, value).await? {
                        return Err(DomainError::InternalError(format!(
                            "Number {} is already assigned to another user/group",
                            value
                        )));
                    }
                }
                // NOTE: gidnumber on *users* deliberately allows duplicates
            }
        }

        let update_user = model::users::ActiveModel {
            user_id: ActiveValue::Set(request.user_id.clone()),
            email: request.email.map(ActiveValue::Set).unwrap_or_default(),
            lowercase_email: lower_email.map(ActiveValue::Set).unwrap_or_default(),
            display_name: to_value(&request.display_name),
            modified_date: ActiveValue::Set(now),
            ..Default::default()
        };
        update_user.update(transaction).await?;

        if !remove_user_attributes.is_empty() {
            model::UserAttributes::delete_many()
                .filter(model::UserAttributesColumn::UserId.eq(&request.user_id))
                .filter(model::UserAttributesColumn::AttributeName.is_in(remove_user_attributes))
                .exec(transaction)
                .await?;
        }

        if !update_user_attributes.is_empty() {
            model::UserAttributes::insert_many(update_user_attributes)
                .on_conflict(
                    OnConflict::columns([
                        model::UserAttributesColumn::UserId,
                        model::UserAttributesColumn::AttributeName,
                    ])
                    .update_column(model::UserAttributesColumn::Value)
                    .to_owned(),
                )
                .exec(transaction)
                .await?;
        }

        match kerb_sync_enabled {
            Some(false) => {
                // Clear the field in our DB
                let update = model::users::ActiveModel {
                    user_id: ActiveValue::Set(request.user_id.clone()),
                    krb_principal_name: ActiveValue::Set(None),
                    modified_date: ActiveValue::Set(now),
                    ..Default::default()
                };
                update.update(transaction).await?;

                // === Actually delete the principal from the Kerberos KDC ===
                if let Err(e) = delete_kerberos_principal(request.user_id.as_str()) {
                    tracing::warn!(
                        "Failed to delete Kerberos principal for user {} when disabling sync: {}",
                        request.user_id,
                        e
                    );
                }
            }
            Some(true) => {}
            None => {}
        }

        Ok(())
    }
}

#[async_trait]
impl SystemConfigBackendHandler for SqlBackendHandler {
    async fn get_allowed_ous(&self) -> Result<Vec<String>> {
        let config = system_config::Entity::find()
            .filter(system_config::Column::Key.eq("allowedous"))
            .one(&self.sql_pool)
            .await?;

        let json_str = config.map(|c| c.value).unwrap_or_else(|| "[]".to_string());
        Ok(serde_json::from_str(&json_str)
            .unwrap_or_else(|_| vec!["people".to_string(), "groups".to_string()]))
    }

    async fn set_system_config(&self, key: &str, value: String) -> Result<()> {
        let config = system_config::ActiveModel {
            key: Set(key.to_string()),
            value: Set(value),
        };

        system_config::Entity::insert(config)
            .on_conflict(
                OnConflict::column(system_config::Column::Key)
                    .update_column(system_config::Column::Value)
                    .to_owned(),
            )
            .exec(&self.sql_pool)
            .await?;

        Ok(())
    }

    #[instrument(skip(self), level = "debug", err)]
    async fn ensure_kerberos_principal_consistency(
        &self,
        user_id: &UserId,
        enabled: bool,
    ) -> Result<()> {
        use chrono::Utc;

        let now = Utc::now().naive_utc();

        if enabled {
            let principal = lldap_kerberos::get_kerberos_principal_name(user_id.as_str());
            tracing::info!(
                "Kerberos sync succeeded → injecting protected krbPrincipalName = {} for user {}",
                principal,
                user_id
            );

            let update = model::users::ActiveModel {
                user_id: ActiveValue::Set(user_id.clone()),
                krb_principal_name: ActiveValue::Set(Some(principal)),
                modified_date: ActiveValue::Set(now),
                ..Default::default()
            };
            update
                .update(&self.sql_pool)
                .await
                .map_err(lldap_domain_model::error::DomainError::DatabaseError)?;
        } else {
            tracing::info!(
                "Kerberos sync disabled → clearing krbPrincipalName for user {}",
                user_id
            );

            let update = model::users::ActiveModel {
                user_id: ActiveValue::Set(user_id.clone()),
                krb_principal_name: ActiveValue::Set(None),
                modified_date: ActiveValue::Set(now),
                ..Default::default()
            };
            update
                .update(&self.sql_pool)
                .await
                .map_err(lldap_domain_model::error::DomainError::DatabaseError)?;
        }
        Ok(())
    }
}

// === FULL POSIX SETTINGS (single source of truth - matches PublicSchema) ===
impl SqlBackendHandler {
    pub async fn get_posix_settings(&self) -> Result<PosixSettings> {
        let config = system_config::Entity::find()
            .filter(system_config::Column::Key.eq("posix_settings"))
            .one(&self.sql_pool)
            .await?;

        let json_str = config
            .map(|c| c.value)
            .unwrap_or_else(|| serde_json::to_string(&PosixSettings::default()).unwrap());

        serde_json::from_str(&json_str).map_err(|e| {
            DomainError::InternalError(format!("Failed to parse posix_settings JSON: {}", e))
        })
    }

    pub async fn set_posix_settings(&self, settings: PosixSettings) -> Result<()> {
        let json = serde_json::to_string(&settings).map_err(|e| {
            DomainError::InternalError(format!("Failed to serialize posix_settings: {}", e))
        })?;
        self.set_system_config("posix_settings", json).await
    }

    // Private transaction-safe helpers
    pub(crate) async fn get_posix_settings_with_transaction(
        transaction: &DatabaseTransaction,
    ) -> Result<PosixSettings> {
        let config = system_config::Entity::find()
            .filter(system_config::Column::Key.eq("posix_settings"))
            .one(transaction)
            .await?;

        let json_str = config
            .map(|c| c.value)
            .unwrap_or_else(|| serde_json::to_string(&PosixSettings::default()).unwrap());

        serde_json::from_str(&json_str).map_err(|e| {
            DomainError::InternalError(format!("Failed to parse posix_settings JSON: {}", e))
        })
    }

    // === NEXT AVAILABLE POSIX NUMBER HELPERS (respect admin overrides + skip collisions) ===
    pub(crate) async fn next_available_uid_number(
        transaction: &DatabaseTransaction,
        start: i64,
        max: i64,
    ) -> Result<i64> {
        if start > max {
            return Err(DomainError::InternalError(format!(
                "uidNumber start ({}) > max ({})",
                start, max
            )));
        }
        let mut candidate = start;
        while candidate <= max {
            if !Self::is_uidnumber_taken(transaction, candidate).await? {
                return Ok(candidate);
            }
            candidate += 1;
        }
        Err(DomainError::InternalError(format!(
            "No available uidNumber in range {}-{} (all taken)",
            start, max
        )))
    }

    pub(crate) async fn next_available_gid_number(
        transaction: &DatabaseTransaction,
        start: i64,
        max: i64,
    ) -> Result<i64> {
        if start > max {
            return Err(DomainError::InternalError(format!(
                "gidNumber start ({}) > max ({})",
                start, max
            )));
        }
        let mut candidate = start;
        while candidate <= max {
            if !Self::is_gidnumber_taken(transaction, candidate).await? {
                return Ok(candidate);
            }
            candidate += 1;
        }
        Err(DomainError::InternalError(format!(
            "No available gidNumber in range {}-{} (all taken)",
            start, max
        )))
    }

    // === DUPLICATE NUMBER ENFORCEMENT HELPERS (uidnumber uniqueness for users; gidnumber uniqueness for groups) ===
    pub(crate) async fn is_uidnumber_taken(
        transaction: &DatabaseTransaction,
        uid: i64,
    ) -> Result<bool> {
        let count = model::UserAttributes::find()
            .filter(model::UserAttributesColumn::AttributeName.eq("uidnumber"))
            .filter(model::UserAttributesColumn::Value.eq(uid.to_string().into_bytes()))
            .count(transaction)
            .await?;
        Ok(count > 0)
    }

    pub(crate) async fn is_gidnumber_taken(
        transaction: &DatabaseTransaction,
        gid: i64,
    ) -> Result<bool> {
        let count = model::GroupAttributes::find()
            .filter(model::GroupAttributesColumn::AttributeName.eq("gidnumber"))
            .filter(model::GroupAttributesColumn::Value.eq(gid.to_string().into_bytes()))
            .count(transaction)
            .await?;
        Ok(count > 0)
    }

    #[instrument(skip(self), level = "info", err)]
    pub async fn reassign_gid_numbers(&self) -> Result<()> {
        let settings = self.get_posix_settings().await?;
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move {
                    if settings.group_gidnumber_assign {
                        let groups = model::Group::find()
                            .order_by_asc(model::groups::Column::CreationDate)
                            .all(transaction)
                            .await?;
                        for (next_gid, group) in
                            (settings.group_gidnumber_start..).zip(groups.into_iter())
                        {
                            let gid_value = next_gid.to_string().into_bytes();
                            let attr = model::group_attributes::ActiveModel {
                                group_id: Set(group.group_id),
                                attribute_name: Set(AttributeName::from("gidnumber")),
                                value: Set(Serialized(gid_value)),
                            };
                            model::GroupAttributes::insert(attr)
                                .on_conflict(
                                    OnConflict::columns([
                                        model::group_attributes::Column::GroupId,
                                        model::group_attributes::Column::AttributeName,
                                    ])
                                    .update_column(model::group_attributes::Column::Value)
                                    .to_owned(),
                                )
                                .exec(transaction)
                                .await?;
                            let now = chrono::Utc::now().naive_utc();
                            let update = model::groups::ActiveModel {
                                group_id: Set(group.group_id),
                                modified_date: Set(now),
                                ..Default::default()
                            };
                            update.update(transaction).await?;
                        }
                    } else {
                        model::GroupAttributes::delete_many()
                            .filter(model::group_attributes::Column::AttributeName.eq("gidnumber"))
                            .exec(transaction)
                            .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    #[instrument(skip(self), level = "info", err)]
    pub async fn reassign_user_uid_numbers(&self) -> Result<()> {
        let settings = self.get_posix_settings().await?;
        self.sql_pool
            .transaction::<_, (), DomainError>(|tx| {
                Box::pin(async move {
                    if settings.user_uidnumber_assign {
                        let users = model::User::find()
                            .order_by_asc(model::users::Column::CreationDate)
                            .all(tx)
                            .await?;
                        for (next, user) in (settings.user_uidnumber_start..).zip(users.into_iter())
                        {
                            let uid_value = next.to_string().into_bytes();
                            let attr = model::user_attributes::ActiveModel {
                                user_id: Set(user.user_id.clone()),
                                attribute_name: Set(AttributeName::from("uidnumber")),
                                value: Set(Serialized(uid_value)),
                            };
                            model::UserAttributes::insert(attr)
                                .on_conflict(
                                    OnConflict::columns([
                                        model::user_attributes::Column::UserId,
                                        model::user_attributes::Column::AttributeName,
                                    ])
                                    .update_column(model::user_attributes::Column::Value)
                                    .to_owned(),
                                )
                                .exec(tx)
                                .await?;
                            let now = chrono::Utc::now().naive_utc();
                            model::users::ActiveModel {
                                user_id: Set(user.user_id),
                                modified_date: Set(now),
                                ..Default::default()
                            }
                            .update(tx)
                            .await?;
                        }
                    } else {
                        model::UserAttributes::delete_many()
                            .filter(model::user_attributes::Column::AttributeName.eq("uidnumber"))
                            .exec(tx)
                            .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    #[instrument(skip(self), level = "info", err)]
    pub async fn reassign_user_gid_numbers(&self) -> Result<()> {
        let settings = self.get_posix_settings().await?;
        self.sql_pool
            .transaction::<_, (), DomainError>(|tx| {
                Box::pin(async move {
                    if settings.user_gidnumber_assign {
                        // STATIC assignment — every user gets the exact same gidNumber from config
                        let users = model::User::find().all(tx).await?;
                        for user in users {
                            let gid_value = settings.user_gidnumber_start.to_string().into_bytes();
                            let attr = model::user_attributes::ActiveModel {
                                user_id: Set(user.user_id.clone()),
                                attribute_name: Set(AttributeName::from("gidnumber")),
                                value: Set(Serialized(gid_value)),
                            };
                            model::UserAttributes::insert(attr)
                                .on_conflict(
                                    OnConflict::columns([
                                        model::user_attributes::Column::UserId,
                                        model::user_attributes::Column::AttributeName,
                                    ])
                                    .update_column(model::user_attributes::Column::Value)
                                    .to_owned(),
                                )
                                .exec(tx)
                                .await?;
                            let now = chrono::Utc::now().naive_utc();
                            model::users::ActiveModel {
                                user_id: Set(user.user_id),
                                modified_date: Set(now),
                                ..Default::default()
                            }
                            .update(tx)
                            .await?;
                        }
                    } else {
                        // Toggle OFF → delete gidnumber from all users
                        model::UserAttributes::delete_many()
                            .filter(model::user_attributes::Column::AttributeName.eq("gidnumber"))
                            .exec(tx)
                            .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    #[instrument(skip(self), level = "info", err)]
    pub async fn reassign_user_homedirectories(&self) -> Result<()> {
        let settings = self.get_posix_settings().await?;
        self.sql_pool
            .transaction::<_, (), DomainError>(|tx| {
                Box::pin(async move {
                    if settings.user_homedirectory_assign {
                        let users = model::User::find().all(tx).await?;
                        for user in users {
                            let home =
                                format!("{}/{}", settings.user_homedirectory_prefix, user.user_id);
                            let attr = model::user_attributes::ActiveModel {
                                user_id: Set(user.user_id.clone()),
                                attribute_name: Set(AttributeName::from("homedirectory")),
                                value: Set(Serialized(home.into_bytes())),
                            };
                            model::UserAttributes::insert(attr)
                                .on_conflict(
                                    OnConflict::columns([
                                        model::user_attributes::Column::UserId,
                                        model::user_attributes::Column::AttributeName,
                                    ])
                                    .update_column(model::user_attributes::Column::Value)
                                    .to_owned(),
                                )
                                .exec(tx)
                                .await?;
                            let now = chrono::Utc::now().naive_utc();
                            model::users::ActiveModel {
                                user_id: Set(user.user_id),
                                modified_date: Set(now),
                                ..Default::default()
                            }
                            .update(tx)
                            .await?;
                        }
                    } else {
                        model::UserAttributes::delete_many()
                            .filter(
                                model::user_attributes::Column::AttributeName.eq("homedirectory"),
                            )
                            .exec(tx)
                            .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    #[instrument(skip(self), level = "info", err)]
    pub async fn reassign_user_loginshells(&self) -> Result<()> {
        let settings = self.get_posix_settings().await?;
        self.sql_pool
            .transaction::<_, (), DomainError>(|tx| {
                Box::pin(async move {
                    if settings.user_loginshell_assign {
                        let users = model::User::find().all(tx).await?;
                        for user in users {
                            let attr = model::user_attributes::ActiveModel {
                                user_id: Set(user.user_id.clone()),
                                attribute_name: Set(AttributeName::from("loginshell")),
                                value: Set(Serialized(
                                    settings.user_loginshell_default.clone().into_bytes(),
                                )),
                            };
                            model::UserAttributes::insert(attr)
                                .on_conflict(
                                    OnConflict::columns([
                                        model::user_attributes::Column::UserId,
                                        model::user_attributes::Column::AttributeName,
                                    ])
                                    .update_column(model::user_attributes::Column::Value)
                                    .to_owned(),
                                )
                                .exec(tx)
                                .await?;
                            let now = chrono::Utc::now().naive_utc();
                            model::users::ActiveModel {
                                user_id: Set(user.user_id),
                                modified_date: Set(now),
                                ..Default::default()
                            }
                            .update(tx)
                            .await?;
                        }
                    } else {
                        model::UserAttributes::delete_many()
                            .filter(model::user_attributes::Column::AttributeName.eq("loginshell"))
                            .exec(tx)
                            .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }
}

#[async_trait]
impl UserBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str()))]
    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        let mut user = User::from(
            model::User::find_by_id(user_id.to_owned())
                .one(&self.sql_pool)
                .await?
                .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))?,
        );

        let attributes = model::UserAttributes::find()
            .filter(model::UserAttributesColumn::UserId.eq(user_id))
            .order_by_asc(model::UserAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;

        let schema = self.get_schema().await?;
        user.attributes = attributes
            .into_iter()
            .map(|a| {
                let mut attr = deserialize::deserialize_attribute(
                    a.attribute_name,
                    &a.value,
                    schema.user_attributes(),
                )?;

                // Force canonical name on output (defensive against any legacy alias data)
                attr.name = Self::canonical_user_attribute_name(&schema, attr.name.as_str());

                if attr.name.as_str() == "avatar" {
                    debug!("GET_USER_DETAILS: avatar attribute found in EAV");
                }
                Ok(attr)
            })
            .collect::<Result<Vec<_>>>()?;

        user.materialize_protected_fields();
        Ok(user)
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str()))]
    async fn get_user_groups(&self, user_id: &UserId) -> Result<HashSet<GroupDetails>> {
        let user = model::User::find_by_id(user_id.to_owned())
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))?;

        Ok(user
            .find_linked(model::memberships::UserToGroup)
            .all(&self.sql_pool)
            .await?
            .into_iter()
            .map(Into::<GroupDetails>::into)
            .collect())
    }

    #[instrument(skip(self), level = "debug", err, fields(user_id = ?request.user_id.as_str()))]
    async fn create_user(&self, mut request: CreateUserRequest) -> Result<()> {
        let now = chrono::Utc::now().naive_utc();
        let uuid = Uuid::from_name_and_date(request.user_id.as_str(), &now);
        let lower_email = request.email.as_str().to_lowercase();

        let default_ou = self
            .get_allowed_ous()
            .await?
            .into_iter()
            .next()
            .unwrap_or_else(|| "people".to_string());

        if !request.attributes.iter().any(|a| a.name.as_str() == "ou") {
            request.attributes.push(Attribute {
                name: "ou".into(),
                value: AttributeValue::String(Cardinality::Singleton(default_ou)),
            });
        }

        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move {
                    let schema = Self::get_schema_with_transaction(transaction).await?;

                    // === POSIX RANGE + DUPLICATE CHECKS (uidnumber on users; gidnumber uniqueness is group-only) ===
                    let settings = Self::get_posix_settings_with_transaction(transaction).await?;

                    for attr in &request.attributes {
                        let name = attr.name.as_str();
                        let value = match &attr.value {
                            AttributeValue::Integer(Cardinality::Singleton(v)) => *v,
                            _ => continue,
                        };

                        if name == "uidnumber" || name == "gidnumber" {
                            if value != 0 && !(3000..=60000).contains(&value) {
                                return Err(DomainError::InternalError(format!(
                                    "{} must be between 3000 and 60000",
                                    name
                                )));
                            }

                            if name == "uidnumber" {
                                if Self::is_uidnumber_taken(transaction, value).await? {
                                    return Err(DomainError::InternalError(format!(
                                        "Number {} is already assigned to another user/group",
                                        value
                                    )));
                                }
                            }
                            // NOTE: gidnumber on *users* deliberately allows duplicates
                        }
                    }

                    // === POSIX auto-assign for users (uidNumber + gidNumber + loginShell + homeDirectory) ===
                    let mut final_attributes = request.attributes;

                    if settings.user_uidnumber_assign {
                        let already_has_uid = final_attributes
                            .iter()
                            .any(|a| a.name.as_str() == "uidnumber");
                        if !already_has_uid {
                            let next_uid = Self::next_available_uid_number(
                                transaction,
                                settings.user_uidnumber_start,
                                settings.user_uidnumber_max,
                            )
                            .await?;
                            final_attributes.push(Attribute {
                                name: "uidnumber".into(),
                                value: AttributeValue::Integer(Cardinality::Singleton(next_uid)),
                            });
                        }
                    }

                    if settings.user_gidnumber_assign {
                        let already_has_gid = final_attributes
                            .iter()
                            .any(|a| a.name.as_str() == "gidnumber");
                        if !already_has_gid {
                            final_attributes.push(Attribute {
                                name: "gidnumber".into(),
                                value: AttributeValue::Integer(Cardinality::Singleton(
                                    settings.user_gidnumber_start,
                                )),
                            });
                        }
                    }

                    if settings.user_loginshell_assign {
                        let already_has_shell = final_attributes
                            .iter()
                            .any(|a| a.name.as_str() == "loginshell");
                        if !already_has_shell {
                            final_attributes.push(Attribute {
                                name: "loginshell".into(),
                                value: AttributeValue::String(Cardinality::Singleton(
                                    settings.user_loginshell_default.clone(),
                                )),
                            });
                        }
                    }

                    if settings.user_homedirectory_assign {
                        let already_has_home = final_attributes
                            .iter()
                            .any(|a| a.name.as_str() == "homedirectory");
                        if !already_has_home {
                            let home_dir = format!(
                                "{}/{}",
                                settings.user_homedirectory_prefix, request.user_id
                            );
                            final_attributes.push(Attribute {
                                name: "homedirectory".into(),
                                value: AttributeValue::String(Cardinality::Singleton(home_dir)),
                            });
                        }
                    }

                    let new_user = model::users::ActiveModel {
                        user_id: Set(request.user_id.clone()),
                        email: Set(request.email),
                        lowercase_email: Set(lower_email),
                        display_name: to_value(&request.display_name),
                        creation_date: ActiveValue::Set(now),
                        uuid: ActiveValue::Set(uuid),
                        modified_date: ActiveValue::Set(now),
                        password_modified_date: ActiveValue::Set(now),
                        krb_principal_name: ActiveValue::Set(None),
                        ..Default::default()
                    };

                    let _group_id = new_user.insert(transaction).await?.user_id;
                    let mut new_user_attributes = Vec::new();

                    for attribute in final_attributes {
                        let canonical_name = schema
                            .user_attributes()
                            .get_by_name_or_alias(attribute.name.as_str())
                            .map(|s| s.name.clone().into())
                            .unwrap_or_else(|| attribute.name.clone());

                        if schema
                            .user_attributes()
                            .get_attribute_type(attribute.name.as_str())
                            .is_some()
                        {
                            let db_value = attribute_value_to_db_bytes(&attribute.value);
                            new_user_attributes.push(model::user_attributes::ActiveModel {
                                user_id: Set(request.user_id.clone()),
                                attribute_name: Set(canonical_name.clone()),
                                value: Set(Serialized(db_value)),
                            });
                        }
                    }

                    if !new_user_attributes.is_empty() {
                        let _ = model::UserAttributes::insert_many(new_user_attributes)
                            .exec(transaction)
                            .await?;
                    }

                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    #[instrument(skip(self), level = "debug", err, fields(user_id = ?request.user_id.as_str()))]
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(
                    async move { Self::update_user_with_transaction(transaction, request).await },
                )
            })
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str()))]
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        // Kerberos principal must be removed when the user ceases to exist.
        // We do this *before* the hard delete so the row still exists if anything
        // downstream needs it, and because delete_kerberos_principal is idempotent.
        if let Err(e) = delete_kerberos_principal(user_id.as_str()) {
            tracing::warn!(
                "Failed to delete Kerberos principal for user {} during deletion (non-fatal): {}",
                user_id,
                e
            );
        }

        let res = model::User::delete_by_id(user_id.clone())
            .exec(&self.sql_pool)
            .await?;
        if res.rows_affected == 0 {
            return Err(DomainError::EntityNotFound(format!(
                "No such user: '{user_id}'"
            )));
        }
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str(), group_id))]
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        // === CORE GROUP MUTUAL EXCLUSION ===
        let user_groups = self.get_user_groups(user_id).await?;
        let target_group_details = self.get_group_details(group_id).await?;

        let target_name = target_group_details.display_name.as_str();
        let has_admin = user_groups
            .iter()
            .any(|g| g.display_name == "lldap_admin".into());
        let has_disabled = user_groups
            .iter()
            .any(|g| g.display_name == "lldap_disabled".into());

        if (target_name == "lldap_admin" && has_disabled)
            || (target_name == "lldap_disabled" && has_admin)
        {
            return Err(DomainError::InternalError(
                "A user cannot be in both lldap_admin and lldap_disabled groups".to_string(),
            ));
        }

        let user_id = user_id.clone();
        self.sql_pool
            .transaction::<_, _, sea_orm::DbErr>(|transaction| {
                Box::pin(async move {
                    let new_membership = model::memberships::ActiveModel {
                        user_id: ActiveValue::Set(user_id),
                        group_id: ActiveValue::Set(group_id),
                    };
                    new_membership.insert(transaction).await?;

                    let now = chrono::Utc::now().naive_utc();
                    let update_group = model::groups::ActiveModel {
                        group_id: Set(group_id),
                        modified_date: Set(now),
                        ..Default::default()
                    };
                    update_group.update(transaction).await?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str(), group_id))]
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        let user_id = user_id.clone();
        self.sql_pool
            .transaction::<_, _, sea_orm::DbErr>(|transaction| {
                Box::pin(async move {
                    // === LAST ADMIN PROTECTION (backend layer) ===
                    // Prevent removing the final member of lldap_admin, regardless of caller.
                    let group_details = model::Group::find_by_id(group_id)
                        .one(transaction)
                        .await?;
                    if let Some(g) = &group_details {
                        if g.display_name.as_str() == "lldap_admin" {
                            let current_count = model::Membership::find()
                                .filter(model::MembershipColumn::GroupId.eq(group_id))
                                .count(transaction)
                                .await?;
                            if current_count <= 1 {
                                return Err(sea_orm::DbErr::Custom(
                                    "Cannot remove the last member of lldap_admin".to_string(),
                                ));
                            }
                        }
                    }

                    let res = model::Membership::delete_by_id((user_id.clone(), group_id))
                        .exec(transaction)
                        .await?;
                    if res.rows_affected == 0 {
                        return Err(sea_orm::DbErr::Custom(format!(
                            "No such membership: '{user_id}' -> {group_id:?}"
                        )));
                    }

                    let now = chrono::Utc::now().naive_utc();
                    let update_group = model::groups::ActiveModel {
                        group_id: Set(group_id),
                        modified_date: Set(now),
                        ..Default::default()
                    };
                    update_group.update(transaction).await?;
                    Ok(())
                })
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Connection(sea_orm::DbErr::Custom(msg)) => {
                    DomainError::EntityNotFound(msg)
                }
                sea_orm::TransactionError::Transaction(sea_orm::DbErr::Custom(msg)) => {
                    DomainError::EntityNotFound(msg)
                }
                sea_orm::TransactionError::Connection(e) => DomainError::DatabaseError(e),
                sea_orm::TransactionError::Transaction(e) => DomainError::DatabaseError(e),
            })?;
        Ok(())
    }
}

#[async_trait]
impl PosixBackendHandler for SqlBackendHandler {
    async fn get_posix_settings(&self) -> Result<PosixSettings> {
        self.get_posix_settings().await
    }
    async fn set_posix_settings(&self, settings: PosixSettings) -> Result<()> {
        self.set_posix_settings(settings).await
    }
    async fn reassign_gid_numbers(&self) -> Result<()> {
        self.reassign_gid_numbers().await
    }
    async fn reassign_user_uid_numbers(&self) -> Result<()> {
        self.reassign_user_uid_numbers().await
    }
    async fn reassign_user_gid_numbers(&self) -> Result<()> {
        self.reassign_user_gid_numbers().await
    }
    async fn reassign_user_homedirectories(&self) -> Result<()> {
        self.reassign_user_homedirectories().await
    }
    async fn reassign_user_loginshells(&self) -> Result<()> {
        self.reassign_user_loginshells().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::*;
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::requests::CreateGroupRequest;
    use lldap_domain::types::Attribute;
    use lldap_domain_handlers::handler::SubStringFilter;
    use lldap_domain_model::model::UserColumn;
    use pretty_assertions::{assert_eq, assert_ne};

    #[tokio::test]
    async fn test_list_users_no_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(&fixture.handler, None).await;
        assert_eq!(users, vec!["bob", "john", "nogroup", "patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_user_id_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::UserId(UserId::new("bob"))),
        )
        .await;
        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_list_users_display_name_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Equality(
                UserColumn::DisplayName,
                "display bob".to_string(),
            )),
        )
        .await;
        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_list_users_other_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::AttributeEquality(
                AttributeName::from("firstname"), // ← canonical name
                "first bob".to_string().into(),
            )),
        )
        .await;
        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_list_users_email_filter_uppercase_email() {
        let fixture = TestFixture::new().await;
        insert_user_no_password(&fixture.handler, "UppEr").await;
        let users_and_emails = fixture
            .handler
            .list_users(
                Some(UserRequestFilter::Equality(
                    UserColumn::Email,
                    "uPPer@bob.bob".to_string(),
                )),
                false,
            )
            .await
            .unwrap()
            .into_iter()
            .map(|u| (u.user.user_id.to_string(), u.user.email.to_string()))
            .collect::<Vec<_>>();
        assert_eq!(
            users_and_emails,
            vec![("upper".to_owned(), "UppEr@bob.bob".to_owned())]
        );
    }

    #[tokio::test]
    async fn test_list_users_substring_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::And(vec![
                UserRequestFilter::UserIdSubString(SubStringFilter {
                    initial: Some("Pa".to_owned()),
                    any: vec!["rI".to_owned()],
                    final_: Some("K".to_owned()),
                }),
                UserRequestFilter::SubString(
                    UserColumn::DisplayName,
                    SubStringFilter {
                        initial: None,
                        any: vec!["t".to_owned(), "r".to_owned()],
                        final_: None,
                    },
                ),
            ])),
        )
        .await;
        assert_eq!(users, vec!["patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_false_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(&fixture.handler, Some(UserRequestFilter::False)).await;
        assert_eq!(users, Vec::<String>::new());
    }

    #[tokio::test]
    async fn test_list_users_member_of() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::MemberOf("Best Group".into())),
        )
        .await;
        assert_eq!(users, vec!["bob", "patrick"]);
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::MemberOf("best grOUp".into())),
        )
        .await;
        assert_eq!(users, vec!["bob", "patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_member_of_and_uuid() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Or(vec![
                UserRequestFilter::MemberOf("Best Group".into()),
                UserRequestFilter::Equality(UserColumn::Uuid, "abc".to_string()),
            ])),
        )
        .await;
        assert_eq!(users, vec!["bob", "patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_member_of_id() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::MemberOfId(fixture.groups[0])),
        )
        .await;
        assert_eq!(users, vec!["bob", "patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_filter_several_member_of() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::And(vec![
                UserRequestFilter::MemberOf("Best Group".into()),
                UserRequestFilter::MemberOf("Worst Group".into()),
            ])),
        )
        .await;
        assert_eq!(users, vec!["patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_filter_several_member_of_id() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::And(vec![
                UserRequestFilter::MemberOfId(fixture.groups[0]),
                UserRequestFilter::MemberOfId(fixture.groups[1]),
            ])),
        )
        .await;
        assert_eq!(users, vec!["patrick"]);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_list_users_invalid_userid_filter() {
        let fixture = TestFixture::new().await;
        get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Equality(
                UserColumn::UserId,
                "first bob".to_string(),
            )),
        )
        .await;
    }

    #[tokio::test]
    async fn test_list_users_filter_or() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Or(vec![
                UserRequestFilter::UserId(UserId::new("bob")),
                UserRequestFilter::UserId(UserId::new("John")),
            ])),
        )
        .await;
        assert_eq!(users, vec!["bob", "john"]);
    }

    #[tokio::test]
    async fn test_list_users_filter_many_or() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Or(vec![
                UserRequestFilter::False,
                UserRequestFilter::Or(vec![
                    UserRequestFilter::UserId(UserId::new("bob")),
                    UserRequestFilter::UserId(UserId::new("John")),
                    UserRequestFilter::UserId(UserId::new("random")),
                ]),
            ])),
        )
        .await;
        assert_eq!(users, vec!["bob", "john"]);
    }

    #[tokio::test]
    async fn test_list_users_filter_not() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Not(Box::new(UserRequestFilter::UserId(
                UserId::new("bob"),
            )))),
        )
        .await;
        assert_eq!(users, vec!["john", "nogroup", "patrick"]);
    }

    #[tokio::test]
    async fn test_list_users_with_groups() {
        let fixture = TestFixture::new().await;
        let users = fixture
            .handler
            .list_users(None, true)
            .await
            .unwrap()
            .into_iter()
            .map(|u| {
                (
                    u.user.user_id.to_string(),
                    u.user
                        .display_name
                        .as_deref()
                        .unwrap_or("<unknown>")
                        .to_owned(),
                    u.groups
                        .unwrap_or_default()
                        .into_iter()
                        .map(|g| g.group_id)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            users,
            vec![
                (
                    "bob".to_string(),
                    "display bob".to_string(),
                    vec![fixture.groups[0]]
                ),
                (
                    "john".to_string(),
                    "display John".to_string(),
                    vec![fixture.groups[1]]
                ),
                ("nogroup".to_string(), "display NoGroup".to_string(), vec![]),
                (
                    "patrick".to_string(),
                    "display patrick".to_string(),
                    vec![fixture.groups[0], fixture.groups[1]]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_list_users_groups_have_different_creation_date_than_users() {
        let fixture = TestFixture::new().await;
        let users = fixture
            .handler
            .list_users(None, true)
            .await
            .unwrap()
            .into_iter()
            .map(|u| {
                (
                    u.user.creation_date,
                    u.groups
                        .unwrap_or_default()
                        .into_iter()
                        .map(|g| g.creation_date)
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        for (user_date, groups) in users {
            for group_date in groups {
                assert_ne!(user_date, group_date);
            }
        }
    }

    #[tokio::test]
    async fn test_get_user_details() {
        let handler =
            SqlBackendHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user_no_password(&handler, "bob").await;
        {
            let user = handler.get_user_details(&UserId::new("bob")).await.unwrap();
            assert_eq!(user.user_id.as_str(), "bob");
        }
        {
            handler
                .get_user_details(&UserId::new("John"))
                .await
                .unwrap_err();
        }
    }

    #[tokio::test]
    async fn test_user_lowercase() {
        let handler =
            SqlBackendHandler::new(generate_random_private_key(), get_initialized_db().await);
        insert_user_no_password(&handler, "Bob").await;
        {
            let user = handler.get_user_details(&UserId::new("bOb")).await.unwrap();
            assert_eq!(user.user_id.as_str(), "bob");
        }
        {
            handler
                .get_user_details(&UserId::new("John"))
                .await
                .unwrap_err();
        }
    }

    #[tokio::test]
    async fn test_delete_user() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .delete_user(&UserId::new("bob"))
            .await
            .unwrap();

        assert_eq!(
            get_user_names(&fixture.handler, None).await,
            vec!["john", "nogroup", "patrick"]
        );

        // Insert new user and remove two
        insert_user_no_password(&fixture.handler, "NewBoi").await;
        fixture
            .handler
            .delete_user(&UserId::new("nogroup"))
            .await
            .unwrap();
        fixture
            .handler
            .delete_user(&UserId::new("NewBoi"))
            .await
            .unwrap();

        assert_eq!(
            get_user_names(&fixture.handler, None).await,
            vec!["john", "patrick"]
        );
    }

    #[tokio::test]
    async fn test_get_user_groups() {
        let fixture = TestFixture::new().await;
        let get_group_ids = async |user: &'static str| {
            let mut groups = fixture
                .handler
                .get_user_groups(&UserId::new(user))
                .await
                .unwrap()
                .into_iter()
                .map(|g| g.group_id)
                .collect::<Vec<_>>();
            groups.sort_by(|g1, g2| g1.0.cmp(&g2.0));
            groups
        };
        assert_eq!(get_group_ids("bob").await, vec![fixture.groups[0]]);
        assert_eq!(
            get_group_ids("patrick").await,
            vec![fixture.groups[0], fixture.groups[1]]
        );
        assert_eq!(get_group_ids("nogroup").await, vec![]);
    }

    #[tokio::test]
    async fn test_update_user_all_values() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                email: Some("email".into()),
                display_name: Some("display_name".to_string()),
                delete_attributes: Vec::new(),
                insert_attributes: vec![
                    Attribute {
                        name: "firstname".into(), // canonical
                        value: "first_name".to_string().into(),
                    },
                    Attribute {
                        name: "lastname".into(), // canonical
                        value: "last_name".to_string().into(),
                    },
                    Attribute {
                        name: "avatar".into(),
                        value: lldap_domain::images::make_test_avatar_value(),
                    },
                ],
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();

        assert_eq!(user.email, "email".into());
        assert_eq!(user.display_name.unwrap(), "display_name");

        // Canonical names + ou + avatar type check (no exact bytes)
        assert!(
            user.attributes.iter().any(
                |a| a.name.as_str() == "avatar" && matches!(a.value, AttributeValue::Avatar(_))
            )
        );
        assert!(
            user.attributes
                .iter()
                .any(|a| a.name.as_str() == "firstname"
                    && a.value == "first_name".to_string().into())
        );
        assert!(user.attributes.iter().any(|a|
        a.name.as_str() == "lastname" && a.value == "last_name".to_string().into()));
        assert!(
            user.attributes
                .iter()
                .any(|a| a.name.as_str() == "ou" && a.value == "people".to_string().into())
        );
    }

    #[tokio::test]
    async fn test_update_user_some_values() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                delete_attributes: vec!["last_name".into()],
                insert_attributes: vec![Attribute {
                    name: "avatar".into(),
                    value: lldap_domain::images::make_test_avatar_value(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();

        assert_eq!(user.display_name.unwrap(), "display bob");

        // Verify canonical names + correct types (image conversion verified in images.rs)
        assert!(
            user.attributes.iter().any(
                |a| a.name.as_str() == "avatar" && matches!(a.value, AttributeValue::Avatar(_))
            )
        );

        assert!(
            user.attributes.iter().any(
                |a| a.name.as_str() == "firstname" && a.value == "first bob".to_string().into()
            )
        );

        assert!(
            user.attributes
                .iter()
                .any(|a| a.name.as_str() == "ou" && a.value == "people".to_string().into())
        );
    }

    #[tokio::test]
    async fn test_update_user_insert_attribute() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                insert_attributes: vec![Attribute {
                    name: "firstname".into(), // canonical
                    value: "new first".to_string().into(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();

        assert_eq!(
            user.attributes,
            vec![
                Attribute {
                    name: "firstname".into(),
                    value: "new first".to_string().into()
                },
                Attribute {
                    name: "lastname".into(),
                    value: "last bob".to_string().into()
                },
                Attribute {
                    name: "ou".into(),
                    value: "people".to_string().into()
                }
            ]
        );
    }

    #[tokio::test]
    async fn test_update_user_delete_attribute() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                delete_attributes: vec!["firstname".into()], // canonical
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();

        assert_eq!(
            user.attributes,
            vec![
                Attribute {
                    name: "lastname".into(),
                    value: "last bob".to_string().into()
                },
                Attribute {
                    name: "ou".into(),
                    value: "people".to_string().into()
                }
            ]
        );
    }

    #[tokio::test]
    async fn test_update_user_replace_attribute() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                delete_attributes: vec!["firstname".into()],
                insert_attributes: vec![Attribute {
                    name: "firstname".into(),
                    value: "new first".to_string().into(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();

        assert_eq!(
            user.attributes,
            vec![
                Attribute {
                    name: "firstname".into(),
                    value: "new first".to_string().into()
                },
                Attribute {
                    name: "lastname".into(),
                    value: "last bob".to_string().into()
                },
                Attribute {
                    name: "ou".into(),
                    value: "people".to_string().into()
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_update_user_delete_avatar() {
        let fixture = TestFixture::new().await;

        // First insert an avatar
        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                insert_attributes: vec![Attribute {
                    name: "avatar".into(),
                    value: lldap_domain::images::make_test_avatar_value(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert!(user.attributes.iter().any(|a| a.name.as_str() == "avatar"));

        // Now delete it
        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                delete_attributes: vec!["avatar".into()],
                ..Default::default()
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .unwrap();
        assert!(!user.attributes.iter().any(|a| a.name.as_str() == "avatar"));
    }

    #[tokio::test]
    async fn test_create_user_all_values() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("james"),
                email: "email".into(),
                display_name: Some("display_name".to_string()),
                attributes: vec![
                    Attribute {
                        name: "firstname".into(),
                        value: "First Name".to_string().into(),
                    },
                    Attribute {
                        name: "lastname".into(),
                        value: "last_name".to_string().into(),
                    },
                    Attribute {
                        name: "avatar".into(),
                        value: lldap_domain::images::make_test_avatar_value(),
                    },
                ],
            })
            .await
            .unwrap();

        let user = fixture
            .handler
            .get_user_details(&UserId::new("james"))
            .await
            .unwrap();

        assert_eq!(user.email, "email".into());
        assert_eq!(user.display_name.unwrap(), "display_name");

        assert!(
            user.attributes.iter().any(
                |a| a.name.as_str() == "avatar" && matches!(a.value, AttributeValue::Avatar(_))
            )
        );
        assert!(
            user.attributes
                .iter()
                .any(|a| a.name.as_str() == "firstname"
                    && a.value == "First Name".to_string().into())
        );
        assert!(user.attributes.iter().any(|a|
        a.name.as_str() == "lastname" && a.value == "last_name".to_string().into()));
        assert!(
            user.attributes
                .iter()
                .any(|a| a.name.as_str() == "ou" && a.value == "people".to_string().into())
        );
    }

    #[tokio::test]
    async fn test_remove_user_from_group() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .remove_user_from_group(&UserId::new("bob"), fixture.groups[0])
            .await
            .unwrap();

        assert_eq!(
            get_user_names(
                &fixture.handler,
                Some(UserRequestFilter::MemberOfId(fixture.groups[0])),
            )
            .await,
            vec!["patrick"]
        );
    }

    #[tokio::test]
    async fn test_cannot_remove_last_member_of_lldap_admin() {
        let fixture = TestFixture::new().await;

        // Create a group that matches the protected admin name
        let admin_gid = fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "lldap_admin".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        // Add exactly one user to it
        fixture
            .handler
            .add_user_to_group(&UserId::new("bob"), admin_gid)
            .await
            .unwrap();

        // Attempting to remove that last member must be rejected by the backend guard
        let err = fixture
            .handler
            .remove_user_from_group(&UserId::new("bob"), admin_gid)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("last member of lldap_admin"),
            "expected last-admin protection, got: {}",
            err
        );

        // The membership should still exist
        let still_member = fixture
            .handler
            .list_users(
                Some(UserRequestFilter::MemberOfId(admin_gid)),
                false,
            )
            .await
            .unwrap();
        assert_eq!(still_member.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_user_not_found() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .delete_user(&UserId::new("not found"))
            .await
            .expect_err("Should have failed");
    }

    #[tokio::test]
    async fn test_remove_user_from_group_not_found() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .remove_user_from_group(&UserId::new("not found"), fixture.groups[0])
            .await
            .expect_err("Should have failed");

        fixture
            .handler
            .remove_user_from_group(&UserId::new("not found"), GroupId(16242))
            .await
            .expect_err("Should have failed");
    }

    #[tokio::test]
    async fn test_create_user_duplicate_email() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("james"),
                email: "email".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("john"),
                email: "eMail".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
    }
}
