use crate::sql_backend_handler::{
    SqlBackendHandler, attribute_value_to_db_bytes, bool_to_expr, get_repeated_filter,
    is_backend_writable_readonly_attribute,
};
use async_trait::async_trait;
use itertools::Itertools;
use lldap_domain::{
    requests::{CreateUserRequest, UpdateUserRequest},
    types::{
        Attribute, AttributeName, AttributeValue, Cardinality, GroupDetails, GroupId, Serialized,
        User, UserAndGroups, UserId, Uuid, kerberos_sync_enabled,
    },
};
use lldap_domain_handlers::handler::{
    GroupBackendHandler, ReadSchemaBackendHandler, SubStringFilter, SystemConfigBackendHandler,
    UserBackendHandler, UserListerBackendHandler, UserRequestFilter,
};
use lldap_domain_handlers::kerberos::{
    kerberos_backend, principal_name, require_kdc_ready, validate_kerberos_username,
};
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, GroupColumn, UserColumn, codec, system_config},
};
use lldap_schema::{KERBEROS_SYNC, PublicSchema};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseTransaction, EntityTrait, ModelTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set, TransactionTrait,
    sea_query::{
        Alias, Cond, Expr, Func, IntoColumnRef, IntoCondition, SimpleExpr, query::OnConflict,
    },
};
use std::collections::HashSet;
use tracing::{debug, instrument};

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
    match filter {
        True => bool_to_expr(true),
        False => bool_to_expr(false),
        And(fs) => get_repeated_filter(fs, Cond::all(), true, get_user_filter_expr),
        Or(fs) => get_repeated_filter(fs, Cond::any(), false, get_user_filter_expr),
        Not(f) => get_user_filter_expr(*f).not(),
        UserId(user_id) => ColumnTrait::eq(&UserColumn::UserId, user_id).into_condition(),
        Equality(column, value) => {
            if column == UserColumn::UserId {
                panic!("User id should be wrapped")
            } else if column == UserColumn::Email {
                ColumnTrait::eq(&UserColumn::LowercaseEmail, value.as_str().to_lowercase())
                    .into_condition()
            } else if column == UserColumn::DisplayName {
                // cn/displayName is caseIgnoreMatch: lower both sides (as the substring path does).
                SimpleExpr::FunctionCall(Func::lower(Expr::col(column.as_column_ref())))
                    .eq(value.to_lowercase())
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

#[async_trait]
impl UserListerBackendHandler for SqlBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn list_users(
        &self,
        filters: Option<UserRequestFilter>,
        // To simplify the query, we always fetch groups. TODO: cleanup.
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
        // TODO: should be wrapped in a transaction
        let schema = self.get_schema().await?;
        for user in users.iter_mut() {
            let mut attrs: Vec<_> = attributes_iter
                .take_while_ref(|u| u.user_id == user.user.user_id)
                .map(|a| {
                    codec::decode_attribute(a.attribute_name, &a.value, schema.user_attributes())
                })
                .collect::<Result<Vec<_>>>()?;

            // Canonical names on the read path, whatever alias legacy rows carry.
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

            if attribute.name.as_str() == KERBEROS_SYNC {
                kerb_sync_enabled = match &attribute.value {
                    AttributeValue::String(Cardinality::Singleton(s)) => match s.trim() {
                        "1" | "true" | "TRUE" => Some(true),
                        "0" | "false" | "FALSE" => Some(false),
                        _ => Some(false),
                    },
                    AttributeValue::Integer(Cardinality::Singleton(1)) => Some(true),
                    AttributeValue::Integer(Cardinality::Singleton(0)) => Some(false),
                    _ => Some(false),
                };
            }

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

    /// Returns whether the caller must delete the user's KDC principal once the
    /// transaction has committed.
    async fn update_user_with_transaction(
        transaction: &DatabaseTransaction,
        request: UpdateUserRequest,
    ) -> Result<bool> {
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

        let posix_numbers: Vec<(String, i64)> = update_user_attributes
            .iter()
            .filter_map(|attr| match (&attr.attribute_name, &attr.value) {
                (ActiveValue::Set(name), ActiveValue::Set(Serialized(bytes))) => {
                    String::from_utf8(bytes.clone())
                        .ok()
                        .map(|s| (name.as_str().to_owned(), s.trim().parse().unwrap_or(0)))
                }
                _ => None,
            })
            .collect();
        Self::validate_posix_numbers(transaction, &posix_numbers, Some(&request.user_id)).await?;

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

        let delete_principal = matches!(kerb_sync_enabled, Some(false));
        if delete_principal {
            let update = model::users::ActiveModel {
                user_id: ActiveValue::Set(request.user_id.clone()),
                krb_principal_name: ActiveValue::Set(None),
                modified_date: ActiveValue::Set(now),
                ..Default::default()
            };
            update.update(transaction).await?;
        }

        Ok(delete_principal)
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
        require_kdc_ready()?;
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
}

impl SqlBackendHandler {
    /// Best-effort: mirror `lldap_disabled` group membership onto the user's Kerberos principal via
    /// Best-effort: mirror `lldap_disabled` membership onto the principal's DISALLOW_ALL_TIX,
    /// only for kerberossync-managed users. Kerberos is advisory here, like `delete_user`.
    async fn reflect_kerberos_disabled(&self, user_id: &UserId, disabled: bool) {
        let synced = match self.get_user_details(user_id).await {
            Ok(u) => kerberos_sync_enabled(&u.attributes),
            Err(e) => {
                tracing::warn!(
                    "Kerberos disable-sync: could not load user {} ({}); skipping",
                    user_id,
                    e
                );
                return;
            }
        };
        if !synced {
            return; // no KLLDAP-managed principal to touch
        }
        if let Err(e) = kerberos_backend().set_principal_enabled(user_id.as_str(), !disabled) {
            tracing::warn!(
                "Failed to {} Kerberos principal for {} (non-fatal): {}",
                if disabled { "disable" } else { "enable" },
                user_id,
                e
            );
        }
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
                let mut attr =
                    codec::decode_attribute(a.attribute_name, &a.value, schema.user_attributes())?;

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
        require_kdc_ready()?;
        validate_kerberos_username(request.user_id.as_str()).map_err(DomainError::InternalError)?;
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

                    let settings = Self::get_posix_settings_with_transaction(transaction).await?;
                    let posix_numbers: Vec<(String, i64)> = request
                        .attributes
                        .iter()
                        .filter_map(|attr| match &attr.value {
                            AttributeValue::Integer(Cardinality::Singleton(value))
                                if *value != 0 =>
                            {
                                Some((attr.name.as_str().to_owned(), *value))
                            }
                            _ => None,
                        })
                        .collect();
                    Self::validate_posix_numbers(transaction, &posix_numbers, None).await?;

                    let mut final_attributes = request.attributes;
                    Self::assign_posix_defaults(
                        transaction,
                        &settings,
                        &request.user_id,
                        &mut final_attributes,
                    )
                    .await?;

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
        require_kdc_ready()?;
        let user_id = request.user_id.clone();
        let delete_principal = self
            .sql_pool
            .transaction::<_, bool, DomainError>(|transaction| {
                Box::pin(
                    async move { Self::update_user_with_transaction(transaction, request).await },
                )
            })
            .await?;
        // KDC side effects run after commit so a rollback cannot orphan a deleted principal.
        if delete_principal && let Err(e) = kerberos_backend().delete_principal(user_id.as_str()) {
            tracing::warn!(
                "Failed to delete Kerberos principal for user {} when disabling sync: {}",
                user_id,
                e
            );
        }
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str()))]
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        require_kdc_ready()?;
        let groups = self.get_user_groups(user_id).await?;
        if groups
            .iter()
            .any(|g| g.display_name == "lldap_admin".into())
        {
            let admins = self
                .list_users(
                    Some(UserRequestFilter::MemberOf("lldap_admin".into())),
                    false,
                )
                .await?;
            if admins.len() <= 1 {
                return Err(DomainError::InternalError(
                    "Cannot delete the last member of lldap_admin".to_string(),
                ));
            }
        }
        // Removed before the row delete, and idempotent, so a missing principal is fine.
        if let Err(e) = kerberos_backend().delete_principal(user_id.as_str()) {
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
        require_kdc_ready()?;
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

        // Captured before the user_id shadow so the post-commit reflect keeps the original id.
        let disabled_target = target_name == "lldap_disabled";
        let kerb_uid = user_id.clone();

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

        // On disable, revoke KDC ticket issuance for kerberossync-managed users (best-effort).
        if disabled_target {
            self.reflect_kerberos_disabled(&kerb_uid, true).await;
        }
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str(), group_id))]
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        require_kdc_ready()?;
        // Resolved before the user_id shadow; a lookup failure skips the best-effort reflect.
        let disabled_target = self
            .get_group_details(group_id)
            .await
            .map(|g| g.display_name.as_str() == "lldap_disabled")
            .unwrap_or(false);
        let kerb_uid = user_id.clone();

        let user_id = user_id.clone();
        self.sql_pool
            .transaction::<_, _, sea_orm::DbErr>(|transaction| {
                Box::pin(async move {
                    // The last member of lldap_admin cannot be removed, whoever asks.
                    let group_details = model::Group::find_by_id(group_id).one(transaction).await?;
                    if let Some(g) = &group_details
                        && g.display_name.as_str() == "lldap_admin"
                    {
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

        // On re-enable, restore KDC ticket issuance for kerberossync-managed users (best-effort).
        if disabled_target {
            self.reflect_kerberos_disabled(&kerb_uid, false).await;
        }
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
            let principal = principal_name(user_id.as_str());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::*;
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::requests::CreateGroupRequest;
    use lldap_domain::types::Attribute;
    use lldap_domain_handlers::handler::SubStringFilter;
    use lldap_domain_model::model::UserColumn;
    use lldap_test_utils::recording_kerberos::{KerberosOp, RecordingGuard};
    use pretty_assertions::{assert_eq, assert_ne};
    use serial_test::serial;

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
    async fn test_list_users_display_name_filter_is_case_insensitive() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::Equality(
                UserColumn::DisplayName,
                "DISPLAY BOB".to_string(),
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
                AttributeName::from("firstname"),
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
    #[serial]
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
            groups.sort_by_key(|g| g.0);
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

    // Toggling lldap_disabled fires a best-effort Kerberos enable/disable that never
    // becomes a hard error.
    #[tokio::test]
    #[serial]
    async fn test_toggle_lldap_disabled_runs_kerberos_hook_cleanly() {
        let guard = RecordingGuard::install();
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("ksync"),
                email: "ksync@example.com".into(),
                display_name: Some("Ksync".to_string()),
                attributes: vec![Attribute {
                    name: "kerberossync".into(),
                    value: 1i64.into(),
                }],
            })
            .await
            .unwrap();

        let disabled_gid = fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "lldap_disabled".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        fixture
            .handler
            .add_user_to_group(&UserId::new("ksync"), disabled_gid)
            .await
            .unwrap();
        assert_eq!(
            get_user_names(
                &fixture.handler,
                Some(UserRequestFilter::MemberOfId(disabled_gid)),
            )
            .await,
            vec!["ksync"]
        );
        assert_eq!(
            guard.recorder().take_ops(),
            vec![KerberosOp::SetEnabled {
                username: "ksync".into(),
                enabled: false,
            }]
        );

        fixture
            .handler
            .remove_user_from_group(&UserId::new("ksync"), disabled_gid)
            .await
            .unwrap();
        assert!(
            get_user_names(
                &fixture.handler,
                Some(UserRequestFilter::MemberOfId(disabled_gid)),
            )
            .await
            .is_empty()
        );
        assert_eq!(
            guard.recorder().take_ops(),
            vec![KerberosOp::SetEnabled {
                username: "ksync".into(),
                enabled: true,
            }]
        );
    }

    #[tokio::test]
    async fn test_cannot_remove_last_member_of_lldap_admin() {
        let fixture = TestFixture::new().await;

        let admin_gid = fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "lldap_admin".into(),
                ..Default::default()
            })
            .await
            .unwrap();

        fixture
            .handler
            .add_user_to_group(&UserId::new("bob"), admin_gid)
            .await
            .unwrap();

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

        let still_member = fixture
            .handler
            .list_users(Some(UserRequestFilter::MemberOfId(admin_gid)), false)
            .await
            .unwrap();
        assert_eq!(still_member.len(), 1);
    }

    #[tokio::test]
    async fn test_cannot_delete_last_lldap_admin_user() {
        let fixture = TestFixture::new().await;
        let admin_gid = fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "lldap_admin".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        fixture
            .handler
            .add_user_to_group(&UserId::new("bob"), admin_gid)
            .await
            .unwrap();
        let err = fixture
            .handler
            .delete_user(&UserId::new("bob"))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("last member of lldap_admin"),
            "expected last-admin delete protection, got: {err}"
        );
        fixture
            .handler
            .get_user_details(&UserId::new("bob"))
            .await
            .expect("last admin must still exist");
    }

    #[tokio::test]
    async fn test_create_user_rejects_reserved_kerberos_name() {
        let fixture = TestFixture::new().await;
        let err = fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("krbtgt"),
                email: "krbtgt@example.com".into(),
                display_name: None,
                attributes: Vec::new(),
            })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("reserved"),
            "expected reserved principal rejection, got: {err}"
        );
    }

    #[tokio::test]
    #[serial]
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

    #[tokio::test]
    #[serial]
    async fn test_disable_sync_deletes_principal_after_commit() {
        let guard = RecordingGuard::install();
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                email: None,
                display_name: None,
                delete_attributes: Vec::new(),
                insert_attributes: vec![Attribute {
                    name: "kerberossync".into(),
                    value: 0i64.into(),
                }],
            })
            .await
            .unwrap();
        assert_eq!(
            guard.recorder().take_ops(),
            vec![KerberosOp::DeletePrincipal {
                username: "bob".into(),
            }]
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_user_emits_delete_principal() {
        let guard = RecordingGuard::install();
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .delete_user(&UserId::new("bob"))
            .await
            .unwrap();
        assert_eq!(
            guard.recorder().take_ops(),
            vec![KerberosOp::DeletePrincipal {
                username: "bob".into(),
            }]
        );
    }
}
