use crate::sql_backend_handler::{
    SqlBackendHandler, attribute_value_to_db_bytes, bool_to_expr, describe_changes,
    get_repeated_filter, is_backend_writable_readonly_attribute,
};
use crate::sql_delete_marks::mark_deleted;
use crate::sql_kerberos_committer::synced_on;
use crate::sql_log_handler::to_active_model;
use async_trait::async_trait;
use itertools::Itertools;
use lldap_domain::{
    requests::{CreateUserRequest, UpdateUserRequest},
    types::{
        Attribute, AttributeName, AttributeValue, Cardinality, GroupDetails, GroupId, GroupName,
        Serialized, User, UserAndGroups, UserId, Uuid, kerberos_sync_enabled,
    },
};
use lldap_domain_handlers::enforcement::moves_ou;
use lldap_domain_handlers::handler::{
    GroupBackendHandler, ReadSchemaBackendHandler, SubStringFilter, SystemConfigBackendHandler,
    UserBackendHandler, UserListerBackendHandler, UserRequestFilter,
};
use lldap_domain_handlers::instant::{Timestamp, to_naive};
use lldap_domain_handlers::kerberos::{
    CONFIRMED_FOR_SYNC, CREATE_WITHOUT_SYNC, CommitError, HostRow, KerberosState,
    LEFT_FOR_THE_START_PASS, LEFT_UNTIL_THE_REALM_OPENS, PRINCIPAL_STAYS,
    STATUS_LEFT_DIRECTORY_ONLY, STATUS_LEFT_DISABLED, STATUS_LEFT_NOT_READY, SYNC_CHANGED,
    SYNC_ON_NEEDS_KERBEROS, UserChange, UserStep, delete_unconfirmed, kerberos_backend,
    kerberos_state, require_kdc_ready, require_settled, sync_refused, unsettled_answer,
    validate_directory_username, validate_kerberos_username, while_disabled,
};
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_domain_handlers::mfa::MFA_DISABLED_GROUP;
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, GroupColumn, UserColumn, codec, system_config},
};
use lldap_schema::{KERBEROS_SYNC, PublicSchema};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    ModelTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set,
    TransactionTrait,
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
    #[instrument(skip(self), level = "debug", ret, err(level = "debug"))]
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

    /// One page: the users' rows, their groups, and of their attributes the OU's alone.
    #[instrument(skip(self), level = "debug", err(level = "debug"))]
    async fn list_users_after(
        &self,
        after: Option<&UserId>,
        limit: usize,
    ) -> Result<Vec<lldap_domain_handlers::handler::ListedUser>> {
        let later = match after {
            Some(after) => ColumnTrait::gt(&UserColumn::UserId, after).into_condition(),
            None => bool_to_expr(true),
        };
        let users = model::User::find()
            .filter(later)
            .order_by_asc(UserColumn::UserId)
            .limit(u64::try_from(limit).unwrap_or(u64::MAX))
            .all(&self.sql_pool)
            .await?;
        let ids: Vec<UserId> = users.iter().map(|user| user.user_id.clone()).collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let name = || {
            SimpleExpr::FunctionCall(Func::lower(Expr::col(
                model::UserAttributesColumn::AttributeName,
            )))
        };
        let ou = PublicSchema::shared()
            .user_attributes()
            .get_by_name_or_alias("ou");
        let names = ou
            .into_iter()
            .flat_map(|ou| std::iter::once(&ou.name).chain(&ou.aliases));
        let named_ou = names.fold(Cond::any().add(name().eq("ou".to_owned())), |any, alias| {
            any.add(name().eq(alias.to_lowercase()))
        });
        let attributes = model::UserAttributes::find()
            .filter(model::UserAttributesColumn::UserId.is_in(ids.clone()))
            .filter(named_ou)
            .order_by_asc(model::UserAttributesColumn::UserId)
            .order_by_asc(model::UserAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;
        let mut ous = std::collections::HashMap::<UserId, Vec<_>>::new();
        for attribute in attributes {
            let of_user = ous.entry(attribute.user_id.clone()).or_default();
            of_user.push(attribute);
        }
        let memberships = model::Membership::find()
            .filter(model::MembershipColumn::UserId.is_in(ids))
            .find_also_related(model::Group)
            .all(&self.sql_pool)
            .await?;
        let mut groups = std::collections::HashMap::<UserId, Vec<GroupDetails>>::new();
        for (membership, group) in memberships {
            let of_user = groups.entry(membership.user_id).or_default();
            of_user.extend(group.map(GroupDetails::from));
        }
        let schema = self.get_schema().await?;
        let listed = users.into_iter().map(|user| -> Result<_> {
            let id = user.user_id.clone();
            let user = Self::user_of((user, ous.remove(&id).unwrap_or_default()), &schema)?;
            let groups = groups.get(&id).map(Vec::as_slice).unwrap_or_default();
            Ok(lldap_domain_handlers::handler::ListedUser::of(
                &user,
                groups.iter(),
            ))
        });
        listed.collect()
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

    /// `update_user` on the caller's transaction, which the Kerberos committer also runs.
    pub(crate) async fn update_user_with_transaction(
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

        if matches!(kerb_sync_enabled, Some(false)) {
            let update = model::users::ActiveModel {
                user_id: ActiveValue::Set(request.user_id.clone()),
                krb_principal_name: ActiveValue::Set(None),
                modified_date: ActiveValue::Set(now),
                ..Default::default()
            };
            update.update(transaction).await?;
        }

        Ok(())
    }

    /// `create_user` on the caller's transaction, which the Kerberos committer also runs.
    pub(crate) async fn create_user_in(
        transaction: &DatabaseTransaction,
        mut request: CreateUserRequest,
    ) -> Result<()> {
        validate_directory_username(request.user_id.as_str())
            .map_err(DomainError::InternalError)?;
        if kerberos_sync_enabled(&request.attributes) {
            validate_kerberos_username(request.user_id.as_str())
                .map_err(|why| DomainError::InternalError(sync_refused(&request.user_id, &why)))?;
        }
        let now = chrono::Utc::now().naive_utc();
        let uuid = Uuid::from_name_and_date(request.user_id.as_str(), &now);
        let lower_email = request.email.as_str().to_lowercase();
        let default_ou = allowed_ous_in(transaction)
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

        let schema = Self::get_schema_with_transaction(transaction).await?;

        let settings = Self::get_posix_settings_with_transaction(transaction).await?;
        let posix_numbers: Vec<(String, i64)> = request
            .attributes
            .iter()
            .filter_map(|attr| match &attr.value {
                AttributeValue::Integer(Cardinality::Singleton(value)) if *value != 0 => {
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
    }
}

/// The sync an update asks for: its `kerberossync` value, or off when it removes the attribute.
fn requested_sync(request: &UpdateUserRequest) -> Option<bool> {
    let schema = PublicSchema::shared();
    let is_sync = |name: &str| schema.resolve_user_canonical_name(name) == Some(KERBEROS_SYNC);
    let inserted = request
        .insert_attributes
        .iter()
        .rfind(|a| is_sync(a.name.as_str()));
    match inserted {
        Some(attribute) => Some(kerberos_sync_enabled(std::slice::from_ref(attribute))),
        None => request
            .delete_attributes
            .iter()
            .any(|name| is_sync(name.as_str()))
            .then_some(false),
    }
}

/// One failure row for a refused user change, and its answer.
fn refused(kind: LogKind, user: &UserId, why: String) -> DomainError {
    logging::record_failure(kind, Some(user.as_str()), &why);
    DomainError::InternalError(why)
}

fn disabled_now() -> Result<bool> {
    require_kdc_ready()?;
    Ok(kerberos_state() == KerberosState::Disabled)
}

fn left_for_the_start_pass(user: &UserId, detail: &str) {
    logging::record(LogKind::KerberosSync, Some(user.as_str()), Some(detail));
}

/// A plain write in directory-only, after it wrote the user's row in `transaction`: a sync change
/// has waited for that row or is read here, and sync on rolls the write back (`SYNC_CHANGED`).
pub(crate) async fn sync_still_off(transaction: &DatabaseTransaction, user: &UserId) -> Result<()> {
    match synced_on(transaction, user).await? {
        true => Err(DomainError::InternalError(SYNC_CHANGED.to_owned())),
        false => Ok(()),
    }
}

async fn commit_life_step(
    user: &UserId,
    step: UserStep,
    mut rows: Vec<HostRow>,
    log: logging::LogEvent,
) -> Option<Result<()>> {
    let kind = log.kind;
    rows.push(HostRow::Log(log));
    let change = UserChange {
        user: user.clone(),
        step,
        rows,
    };
    let done = kerberos_backend().commit_user(change).await?;
    Some(done.map_err(|e| match user_change_error(step, user, e) {
        Ok(why) => refused(kind, user, why),
        Err(gone) => {
            logging::record_failure(kind, Some(user.as_str()), &gone.to_string());
            gone
        }
    }))
}

fn user_change_error(
    step: UserStep,
    user: &UserId,
    e: CommitError,
) -> std::result::Result<String, DomainError> {
    let op = step.op();
    Ok(match e {
        CommitError::UserGone => {
            return Err(DomainError::EntityNotFound(format!(
                "No such user: '{user}'"
            )));
        }
        CommitError::Refused(why) if why == SYNC_CHANGED => why,
        CommitError::Refused(why) if step == UserStep::SyncOn => sync_refused(user, &why),
        CommitError::Busy => "a Kerberos change is in progress, try again".to_owned(),
        CommitError::Unsettled(cause) => return Err(unsettled_answer(&cause)),
        CommitError::Refused(why) | CommitError::Failed(why) => {
            format!("the {op} of user {user} failed: {why}")
        }
        CommitError::Unknown(why) => {
            format!("the result of the {op} of user {user} is unknown: {why}")
        }
    })
}

async fn allowed_ous_in(db: &impl ConnectionTrait) -> Result<Vec<String>> {
    let config = system_config::Entity::find()
        .filter(system_config::Column::Key.eq("allowedous"))
        .one(db)
        .await?;

    let json_str = config.map(|c| c.value).unwrap_or_else(|| "[]".to_string());
    Ok(serde_json::from_str(&json_str)
        .unwrap_or_else(|_| vec!["people".to_string(), "groups".to_string()]))
}

#[async_trait]
impl SystemConfigBackendHandler for SqlBackendHandler {
    async fn get_allowed_ous(&self) -> Result<Vec<String>> {
        allowed_ous_in(&self.sql_pool).await
    }

    async fn set_system_config(&self, key: &str, value: String) -> Result<()> {
        require_kdc_ready()?;
        let config = system_config::ActiveModel {
            key: Set(key.to_string()),
            value: Set(value.clone()),
        };

        system_config::Entity::insert(config)
            .on_conflict(
                OnConflict::column(system_config::Column::Key)
                    .update_column(system_config::Column::Value)
                    .to_owned(),
            )
            .exec(&self.sql_pool)
            .await?;

        let detail = match key {
            "allowedous" | "posix_settings" => value.as_str(),
            _ => "updated",
        };
        logging::record(LogKind::SystemConfigChange, Some(key), Some(detail));
        Ok(())
    }
}

/// An `lldap_disabled` membership in READY, under the realm's write lock, which reads the user's
/// sync again: the membership, its row and a synced user's status in one change. None: the
/// membership commits alone.
async fn commit_status(
    state: &KerberosState,
    user: &UserId,
    group: GroupId,
    add: bool,
    (name, synced): (&str, bool),
) -> Option<Result<()>> {
    if *state != KerberosState::Ready {
        return None;
    }
    let (step, kind) = match add {
        true => (UserStep::Disable, LogKind::MembershipAdd),
        false => (UserStep::Enable, LogKind::MembershipRemove),
    };
    if synced && let Err(refused) = require_settled(kind, user) {
        return Some(Err(refused));
    }
    let log = logging::event(kind, Some(user.as_str()), true, Some(name));
    let membership = HostRow::Membership {
        user: user.clone(),
        group,
        add,
    };
    commit_life_step(user, step, vec![membership], log).await
}

fn status_left(state: &KerberosState, user: &UserId) {
    match state {
        KerberosState::Disabled => left_for_the_start_pass(user, STATUS_LEFT_DISABLED),
        KerberosState::NotReady(_) => left_for_the_start_pass(user, status_left_not_ready()),
        KerberosState::Ready => {}
    }
}

fn status_left_not_ready() -> &'static str {
    match kerberos_backend().directory_only() {
        Some(_) => STATUS_LEFT_DIRECTORY_ONLY,
        None => STATUS_LEFT_NOT_READY,
    }
}

fn is_admin_group(name: &str) -> bool {
    GroupName::from(name) == GroupName::from("lldap_admin")
}

fn is_disabled_group(name: &str) -> bool {
    GroupName::from(name) == GroupName::from("lldap_disabled")
}

impl SqlBackendHandler {
    /// Whether `user_id` has sync, read for an `lldap_disabled` change only.
    async fn synced_for_status(&self, user_id: &UserId, group: Option<&str>) -> Result<bool> {
        if !group.is_some_and(is_disabled_group) {
            return Ok(false);
        }
        let user = self.get_user_details(user_id).await?;
        Ok(kerberos_sync_enabled(&user.attributes))
    }

    /// The delete of a user read without sync in directory-only: the user's row is written first,
    /// then `sync_still_off`, then the delete, in one transaction. The rows deleted.
    async fn delete_with_sync_off(&self, user_id: &UserId) -> Result<u64> {
        let user = user_id.clone();
        let deleted = self
            .sql_pool
            .transaction::<_, u64, DomainError>(|transaction| {
                Box::pin(async move {
                    let now = to_naive(Timestamp::now());
                    model::User::update_many()
                        .col_expr(UserColumn::ModifiedDate, Expr::value(now))
                        .filter(ColumnTrait::eq(&UserColumn::UserId, user.clone()))
                        .exec(transaction)
                        .await?;
                    sync_still_off(transaction, &user).await?;
                    let deleted = model::User::delete_by_id(user).exec(transaction).await?;
                    Ok(deleted.rows_affected)
                })
            })
            .await;
        deleted.map_err(|e| match DomainError::from(e) {
            DomainError::InternalError(why) if why == SYNC_CHANGED => {
                refused(LogKind::UserDelete, user_id, why)
            }
            e => e,
        })
    }

    /// The confirmed delete of a synced user in directory-only: the user's row written first, its
    /// sync read again, the mark, then the delete, in one transaction. The rows deleted.
    async fn delete_leaving_principal(&self, user_id: &UserId) -> Result<u64> {
        let user = user_id.clone();
        let deleted = self
            .sql_pool
            .transaction::<_, u64, DomainError>(|transaction| {
                Box::pin(async move {
                    let now = Timestamp::now();
                    model::User::update_many()
                        .col_expr(UserColumn::ModifiedDate, Expr::value(to_naive(now)))
                        .filter(ColumnTrait::eq(&UserColumn::UserId, user.clone()))
                        .exec(transaction)
                        .await?;
                    if !synced_on(transaction, &user).await? {
                        return Err(DomainError::InternalError(SYNC_CHANGED.to_owned()));
                    }
                    mark_deleted(transaction, user.as_str(), now.as_second()).await?;
                    let deleted = model::User::delete_by_id(user).exec(transaction).await?;
                    Ok(deleted.rows_affected)
                })
            })
            .await;
        deleted.map_err(|e| match DomainError::from(e) {
            DomainError::InternalError(why) if why == SYNC_CHANGED => {
                refused(LogKind::UserDelete, user_id, why)
            }
            e => e,
        })
    }

    async fn delete_user_with(&self, user_id: &UserId, confirmed: bool) -> Result<Option<String>> {
        let disabled = disabled_now()?;
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
        let synced = kerberos_sync_enabled(&self.get_user_details(user_id).await?.attributes);
        if synced
            && !confirmed
            && let Some(unconfirmed) = delete_unconfirmed(user_id)
        {
            return Err(unconfirmed);
        }
        let closed = kerberos_backend().directory_only().is_some();
        let (deleted, warning) = match (closed, synced, confirmed) {
            (true, false, true) => {
                let why = CONFIRMED_FOR_SYNC.to_owned();
                return Err(refused(LogKind::UserDelete, user_id, why));
            }
            (true, true, true) => {
                let deleted = self.delete_leaving_principal(user_id).await?;
                (deleted, Some(PRINCIPAL_STAYS.to_owned()))
            }
            _ => {
                if synced {
                    require_settled(LogKind::UserDelete, user_id)?;
                }
                let step = match synced {
                    true => UserStep::Delete,
                    false => UserStep::DeleteWithoutSync,
                };
                let log = logging::event(LogKind::UserDelete, Some(user_id.as_str()), true, None);
                let rows = vec![
                    HostRow::SyncIs(user_id.clone(), synced),
                    HostRow::DeleteUser(user_id.clone()),
                ];
                if !disabled && let Some(done) = commit_life_step(user_id, step, rows, log).await {
                    if done.is_ok() {
                        self.lockout.forget(user_id);
                    }
                    return done.map(|()| None);
                }
                let deleted = match closed {
                    true => self.delete_with_sync_off(user_id).await?,
                    false => {
                        let res = model::User::delete_by_id(user_id.clone())
                            .exec(&self.sql_pool)
                            .await?;
                        res.rows_affected
                    }
                };
                (deleted, None)
            }
        };
        if deleted == 0 {
            return Err(DomainError::EntityNotFound(format!(
                "No such user: '{user_id}'"
            )));
        }
        self.lockout.forget(user_id);
        self.user_written(user_id).await;
        logging::record(LogKind::UserDelete, Some(user_id.as_str()), None);
        match (warning.is_some(), disabled && synced) {
            (true, _) => left_for_the_start_pass(user_id, LEFT_UNTIL_THE_REALM_OPENS),
            (false, true) => left_for_the_start_pass(user_id, LEFT_FOR_THE_START_PASS),
            (false, false) => {}
        }
        Ok(warning)
    }

    /// The forced reset of an admin whose Kerberos cannot take part: the password, the sync turned
    /// off and `row`, in one transaction.
    pub async fn reset_password_without_sync(
        &self,
        user_id: &UserId,
        password: &[u8],
        row: logging::LogEvent,
    ) -> Result<()> {
        let (record, _) =
            lldap_opaque_handler::prepare_registration(self, user_id.clone(), password).await?;
        let (user, printed) = (user_id.clone(), row.clone());
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move {
                    let now = chrono::Utc::now().naive_utc();
                    let update = model::users::ActiveModel {
                        user_id: ActiveValue::Set(user.clone()),
                        password_hash: ActiveValue::Set(Some(record)),
                        password_modified_date: ActiveValue::Set(now),
                        modified_date: ActiveValue::Set(now),
                        krb_principal_name: ActiveValue::Set(None),
                        ..Default::default()
                    };
                    update.update(transaction).await.map_err(|e| match e {
                        sea_orm::DbErr::RecordNotUpdated => {
                            DomainError::EntityNotFound(format!("No such user: '{user}'"))
                        }
                        e => DomainError::DatabaseError(e),
                    })?;
                    model::UserAttributes::delete_many()
                        .filter(model::UserAttributesColumn::UserId.eq(&user))
                        .filter(
                            model::UserAttributesColumn::AttributeName
                                .eq(AttributeName::new(KERBEROS_SYNC)),
                        )
                        .exec(transaction)
                        .await?;
                    model::Logs::insert(to_active_model(row))
                        .exec_without_returning(transaction)
                        .await?;
                    Ok(())
                })
            })
            .await?;
        logging::print(&printed);
        Ok(())
    }

    /// A membership change on the caller's transaction, which the Kerberos committer also runs.
    pub(crate) async fn change_membership_in(
        transaction: &DatabaseTransaction,
        user_id: UserId,
        group_id: GroupId,
        add: bool,
    ) -> std::result::Result<(), sea_orm::DbErr> {
        if add {
            let new_membership = model::memberships::ActiveModel {
                user_id: ActiveValue::Set(user_id),
                group_id: ActiveValue::Set(group_id),
            };
            new_membership.insert(transaction).await?;
        } else {
            // The last member of lldap_admin cannot be removed, whoever asks.
            let group_details = model::Group::find_by_id(group_id).one(transaction).await?;
            if let Some(g) = &group_details
                && g.display_name == "lldap_admin".into()
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
        }
        let now = chrono::Utc::now().naive_utc();
        let update_group = model::groups::ActiveModel {
            group_id: Set(group_id),
            modified_date: Set(now),
            ..Default::default()
        };
        update_group.update(transaction).await?;
        Ok(())
    }
}

type UserRows = (model::users::Model, Vec<model::user_attributes::Model>);

impl SqlBackendHandler {
    async fn user_rows_on(db: &impl ConnectionTrait, user_id: &UserId) -> Result<UserRows> {
        let user = model::User::find_by_id(user_id.to_owned())
            .one(db)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))?;
        let attributes = model::UserAttributes::find()
            .filter(model::UserAttributesColumn::UserId.eq(user_id))
            .order_by_asc(model::UserAttributesColumn::AttributeName)
            .all(db)
            .await?;
        Ok((user, attributes))
    }

    /// `get_user_details` with every read on `db`, the schema's too.
    pub(crate) async fn user_details_on(
        db: &impl ConnectionTrait,
        user_id: &UserId,
    ) -> Result<User> {
        let rows = Self::user_rows_on(db, user_id).await?;
        let schema = Self::get_schema_with_transaction(db).await?;
        Self::user_of(rows, &schema)
    }

    fn user_of((user, attributes): UserRows, schema: &PublicSchema) -> Result<User> {
        let mut user = User::from(user);
        user.attributes = attributes
            .into_iter()
            .map(|a| {
                let mut attr =
                    codec::decode_attribute(a.attribute_name, &a.value, schema.user_attributes())?;

                attr.name = Self::canonical_user_attribute_name(schema, attr.name.as_str());

                if attr.name.as_str() == "avatar" {
                    debug!("GET_USER_DETAILS: avatar attribute found in EAV");
                }
                Ok(attr)
            })
            .collect::<Result<Vec<_>>>()?;

        user.materialize_protected_fields();
        Ok(user)
    }
}

#[async_trait]
impl UserBackendHandler for SqlBackendHandler {
    #[instrument(skip_all, level = "debug", err(level = "debug"), fields(user_id = ?user_id.as_str()))]
    async fn get_user_details(&self, user_id: &UserId) -> Result<User> {
        let rows = Self::user_rows_on(&self.sql_pool, user_id).await?;
        Self::user_of(rows, &self.get_schema().await?)
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
    async fn create_user(&self, request: CreateUserRequest) -> Result<()> {
        let disabled = disabled_now()?;
        let user_id = request.user_id.clone();
        if kerberos_sync_enabled(&request.attributes) {
            require_settled(LogKind::UserCreate, &user_id)?;
            let refusal = match validate_kerberos_username(user_id.as_str()) {
                Ok(()) if disabled => {
                    let why = CREATE_WITHOUT_SYNC.to_owned();
                    return Err(refused(LogKind::UserCreate, &user_id, why));
                }
                Ok(()) => kerberos_backend().sync_on_refused(&user_id).await,
                named => named,
            };
            if let Err(why) = refusal {
                let why = sync_refused(&user_id, &why);
                return Err(refused(LogKind::UserCreate, &user_id, why));
            }
            let log = logging::event(LogKind::UserCreate, Some(user_id.as_str()), true, None);
            let rows = vec![HostRow::CreateUser(request.clone())];
            if let Some(done) = commit_life_step(&user_id, UserStep::Create, rows, log).await {
                if done.is_ok() {
                    self.lockout.forget(&user_id);
                }
                return done;
            }
        }
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(async move { Self::create_user_in(transaction, request).await })
            })
            .await?;
        self.lockout.forget(&user_id);
        self.user_written(&user_id).await;
        logging::record(LogKind::UserCreate, Some(user_id.as_str()), None);
        Ok(())
    }

    #[instrument(skip(self), level = "debug", err, fields(user_id = ?request.user_id.as_str()))]
    async fn update_user(&self, request: UpdateUserRequest) -> Result<()> {
        let disabled = disabled_now()?;
        let user_id = request.user_id.clone();
        let mut left = false;
        let moves_ou = moves_ou(&request);
        let changes = describe_changes(
            &request.insert_attributes,
            &request.delete_attributes,
            &[
                ("email", request.email.is_some()),
                ("display_name", request.display_name.is_some()),
            ],
        );
        if let Some(on) = requested_sync(&request) {
            let was = kerberos_sync_enabled(&self.get_user_details(&user_id).await?.attributes);
            if on != was {
                require_settled(LogKind::UserUpdate, &user_id)?;
            }
            if on && !was {
                validate_kerberos_username(user_id.as_str()).map_err(|why| {
                    refused(LogKind::UserUpdate, &user_id, sync_refused(&user_id, &why))
                })?;
            }
            if on && !was && disabled {
                let why = while_disabled(SYNC_ON_NEEDS_KERBEROS);
                return Err(refused(LogKind::UserUpdate, &user_id, why));
            }
            left = disabled && was && !on;
            let step = match (was, on) {
                (false, true) => UserStep::SyncOn,
                (true, false) => UserStep::SyncOff,
                _ => UserStep::SyncUnchanged,
            };
            let log = logging::event(
                LogKind::UserUpdate,
                Some(user_id.as_str()),
                true,
                Some(&changes),
            );
            let rows = vec![
                HostRow::SyncIs(user_id.clone(), was),
                HostRow::UpdateUser(request.clone()),
            ];
            if !disabled && let Some(done) = commit_life_step(&user_id, step, rows, log).await {
                return done;
            }
        }
        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(
                    async move { Self::update_user_with_transaction(transaction, request).await },
                )
            })
            .await?;
        if moves_ou {
            self.user_written(&user_id).await;
        }
        logging::record(LogKind::UserUpdate, Some(user_id.as_str()), Some(&changes));
        if left {
            left_for_the_start_pass(&user_id, LEFT_FOR_THE_START_PASS);
        }
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str()))]
    async fn delete_user(&self, user_id: &UserId) -> Result<()> {
        self.delete_user_with(user_id, false).await.map(drop)
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str()))]
    async fn delete_user_confirmed(&self, user_id: &UserId) -> Result<Option<String>> {
        self.delete_user_with(user_id, true).await
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str(), group_id))]
    async fn add_user_to_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        let user_groups = self.get_user_groups(user_id).await?;
        let target_group_details = self.get_group_details(group_id).await?;

        let target_name = target_group_details.display_name.as_str();
        if !is_disabled_group(target_name) {
            require_kdc_ready()?;
        }
        let has_admin = user_groups
            .iter()
            .any(|g| g.display_name == "lldap_admin".into());
        let has_disabled = user_groups
            .iter()
            .any(|g| g.display_name == "lldap_disabled".into());

        if (is_admin_group(target_name) && has_disabled)
            || (is_disabled_group(target_name) && has_admin)
        {
            return Err(DomainError::InternalError(
                "A user cannot be in both lldap_admin and lldap_disabled groups".to_string(),
            ));
        }

        let state = kerberos_state();
        let synced = self.synced_for_status(user_id, Some(target_name)).await?;
        if is_disabled_group(target_name)
            && let Some(done) =
                commit_status(&state, user_id, group_id, true, (target_name, synced)).await
        {
            return done;
        }

        let member = user_id.clone();
        self.sql_pool
            .transaction::<_, _, sea_orm::DbErr>(|transaction| {
                Box::pin(async move {
                    Self::change_membership_in(transaction, member, group_id, true).await
                })
            })
            .await?;
        logging::record(
            LogKind::MembershipAdd,
            Some(user_id.as_str()),
            Some(target_name),
        );
        if target_name == MFA_DISABLED_GROUP {
            self.user_written(user_id).await;
        }
        if synced {
            status_left(&state, user_id);
        }
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err, fields(user_id = ?user_id.as_str(), group_id))]
    async fn remove_user_from_group(&self, user_id: &UserId, group_id: GroupId) -> Result<()> {
        let group_name = self
            .get_group_details(group_id)
            .await
            .ok()
            .map(|g| g.display_name.as_str().to_owned());
        if !group_name.as_deref().is_some_and(is_disabled_group) {
            require_kdc_ready()?;
        }
        let state = kerberos_state();
        let synced = self
            .synced_for_status(user_id, group_name.as_deref())
            .await?;
        let name = group_name.as_deref().unwrap_or_default();
        if is_disabled_group(name)
            && let Some(done) =
                commit_status(&state, user_id, group_id, false, (name, synced)).await
        {
            return done;
        }

        let member = user_id.clone();
        self.sql_pool
            .transaction::<_, _, sea_orm::DbErr>(|transaction| {
                Box::pin(async move {
                    Self::change_membership_in(transaction, member, group_id, false).await
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
        logging::record(
            LogKind::MembershipRemove,
            Some(user_id.as_str()),
            group_name.as_deref(),
        );
        if name == MFA_DISABLED_GROUP {
            self.user_written(user_id).await;
        }
        if synced {
            status_left(&state, user_id);
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
            let principal = kerberos_backend().principal_name(user_id);
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
    use lldap_test_utils::recording_kerberos::{KerberosOp, RECORDER_REALM, RecordingGuard};
    use pretty_assertions::{assert_eq, assert_ne};
    use serial_test::serial;

    #[tokio::test]
    async fn test_list_users_no_filter() {
        let fixture = TestFixture::new().await;
        let users = get_user_names(&fixture.handler, None).await;
        assert_eq!(users, vec!["bob", "john", "nogroup", "patrick"]);
    }

    #[tokio::test]
    async fn test_the_users_are_listed_a_page_at_a_time_in_user_id_order() {
        let fixture = TestFixture::new().await;
        let handler = &fixture.handler;
        let exempt = insert_group(handler, MFA_DISABLED_GROUP).await;
        insert_membership(handler, exempt, "john").await;
        let labs = Attribute {
            name: "ou".into(),
            value: "people\\labs".to_owned().into(),
        };
        let moved = UpdateUserRequest {
            user_id: UserId::new("patrick"),
            insert_attributes: vec![labs],
            ..Default::default()
        };
        handler.update_user(moved).await.unwrap();
        let mut pages = Vec::new();
        let mut after: Option<UserId> = None;
        loop {
            let page = handler.list_users_after(after.as_ref(), 3).await.unwrap();
            let row = page.iter().map(|user| {
                (
                    user.user_id.to_string(),
                    user.ou_key.clone(),
                    user.facts.exempt,
                )
            });
            pages.push(row.collect::<Vec<_>>());
            after = page.last().map(|user| user.user_id.clone());
            if page.len() < 3 {
                break;
            }
        }
        let row = |user: &str, ou: &str, exempt| (user.to_owned(), ou.to_owned(), exempt);
        assert_eq!(
            pages,
            vec![
                vec![
                    row("bob", "people", false),
                    row("john", "people", true),
                    row("nogroup", "people", false)
                ],
                vec![row("patrick", "people\\labs", false)]
            ],
            "pages of three in user-id order, the last one short; each user's OU key from its \
             own attribute, and its exempt group read"
        );
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

    // Directory writes drive the KDC through the seam: a reserved name is refused before
    // any call, and a synced user's lldap_disabled membership, sync change or delete is one
    // change with its principal's.
    #[tokio::test]
    #[serial]
    async fn test_kerberos_hooks_on_directory_writes() {
        let guard = RecordingGuard::install();
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
        assert!(guard.recorder().take_ops().is_empty());

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
        assert_eq!(
            guard.recorder().take_ops(),
            vec![KerberosOp::CommitUser {
                username: "ksync".into(),
                step: "create",
                rows: vec!["create ksync".to_owned(), "log user_create".to_owned()],
            }],
            "a create with sync takes the sync-on step in its own change"
        );
        fixture
            .handler
            .ensure_kerberos_principal_consistency(&UserId::new("ksync"), true)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .handler
                .get_user_details(&UserId::new("ksync"))
                .await
                .unwrap()
                .krb_principal_name,
            Some(format!("ksync@{RECORDER_REALM}")),
            "the principal is named by the registered backend, not the environment"
        );
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
        let status = |step: &'static str, membership: String, log: &str| KerberosOp::CommitUser {
            username: "ksync".into(),
            step,
            rows: vec![membership, log.to_owned()],
        };
        let group = disabled_gid.0;
        assert_eq!(
            guard.recorder().take_ops(),
            vec![status(
                "disable",
                format!("add ksync to group {group}"),
                "log membership_add"
            )]
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
            vec![status(
                "enable",
                format!("remove ksync from group {group}"),
                "log membership_remove"
            )]
        );

        let sync = |user: &str, value: Option<i64>| UpdateUserRequest {
            user_id: UserId::new(user),
            insert_attributes: value
                .map(|value| Attribute {
                    name: "kerberossync".into(),
                    value: value.into(),
                })
                .into_iter()
                .collect(),
            delete_attributes: match value {
                Some(_) => Vec::new(),
                None => vec!["kerberossync".into()],
            },
            ..Default::default()
        };
        let committed = |user: &str, step: &'static str, rows: [&str; 3]| KerberosOp::CommitUser {
            username: user.into(),
            step,
            rows: rows.iter().map(|row| (*row).to_owned()).collect(),
        };
        let synced = async |user: &str| {
            let details = fixture.handler.get_user_details(&UserId::new(user)).await;
            details.map(|u| kerberos_sync_enabled(&u.attributes)).ok()
        };
        let update_rows = |was: &'static str| [was, "update ksync", "log user_update"];
        type Step = (
            &'static str,
            UpdateUserRequest,
            Vec<KerberosOp>,
            Option<bool>,
        );
        let steps: [Step; 5] = [
            (
                "sync off",
                sync("ksync", Some(0)),
                vec![committed("ksync", "sync off", update_rows("synced ksync"))],
                Some(false),
            ),
            (
                "sync off again: the principal is not touched, the sync is checked",
                sync("ksync", Some(0)),
                vec![committed("ksync", "update", update_rows("unsynced ksync"))],
                Some(false),
            ),
            (
                "sync on",
                sync("ksync", Some(1)),
                vec![committed("ksync", "sync on", update_rows("unsynced ksync"))],
                Some(true),
            ),
            (
                "sync off by removing the attribute",
                sync("ksync", None),
                vec![committed("ksync", "sync off", update_rows("synced ksync"))],
                Some(false),
            ),
            (
                "bob was never synced",
                sync("bob", Some(0)),
                vec![committed(
                    "bob",
                    "update",
                    ["unsynced bob", "update bob", "log user_update"],
                )],
                Some(false),
            ),
        ];
        for (label, request, ops, after) in steps {
            let user = request.user_id.clone();
            fixture.handler.update_user(request).await.unwrap();
            assert_eq!(
                (guard.recorder().take_ops(), synced(user.as_str()).await),
                (ops, after),
                "{label}"
            );
        }

        fixture
            .handler
            .update_user(sync("ksync", Some(1)))
            .await
            .unwrap();
        guard.recorder().take_ops();
        for (user, ops) in [
            (
                "ksync",
                vec![committed(
                    "ksync",
                    "delete",
                    ["synced ksync", "delete ksync", "log user_delete"],
                )],
            ),
            (
                "bob",
                vec![committed(
                    "bob",
                    "delete",
                    ["unsynced bob", "delete bob", "log user_delete"],
                )],
            ),
        ] {
            fixture
                .handler
                .delete_user(&UserId::new(user))
                .await
                .unwrap();
            assert_eq!(
                (guard.recorder().take_ops(), synced(user).await),
                (ops, None),
                "delete {user}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_refused_user_change_writes_nothing() {
        use lldap_domain_handlers::kerberos::CommitError;
        use lldap_test_utils::recording_log::LogGuard;
        let fixture = TestFixture::new().await;
        let accepting = RecordingGuard::install();
        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("bob"),
                insert_attributes: vec![Attribute {
                    name: "kerberossync".into(),
                    value: 1i64.into(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();
        drop(accepting);
        let rows = [
            (
                CommitError::Busy,
                "a Kerberos change is in progress, try again",
            ),
            (CommitError::UserGone, "No such user: 'bob'"),
            (
                CommitError::Refused(SYNC_CHANGED.to_owned()),
                "the user's Kerberos sync changed; try again",
            ),
            (
                CommitError::Refused("a row".to_owned()),
                "the delete of user bob failed: a row",
            ),
            (
                CommitError::Failed("the generation moved".to_owned()),
                "the delete of user bob failed: the generation moved",
            ),
            (
                CommitError::Unknown("late".to_owned()),
                "the result of the delete of user bob is unknown: late",
            ),
        ];
        for (answer, text) in rows {
            let log = LogGuard::install_on_this_thread();
            let guard = RecordingGuard::install_answering(Err(answer.clone()));
            let err = fixture
                .handler
                .delete_user(&UserId::new("bob"))
                .await
                .unwrap_err();
            let still = fixture.handler.get_user_details(&UserId::new("bob")).await;
            let failures: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.target.as_deref() == Some("bob"))
                .map(|e| {
                    (
                        e.kind,
                        e.success,
                        e.detail.is_some_and(|d| d.contains(text)),
                    )
                })
                .collect();
            assert_eq!(
                (
                    err.to_string().contains(text),
                    still.is_ok(),
                    guard.recorder().take_ops().len(),
                    failures
                ),
                (true, true, 1, vec![(LogKind::UserDelete, false, true)]),
                "{answer:?}: {err}"
            );
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Life {
        CreateSynced,
        CreateUnsynced,
        SyncOn,
        SyncOff,
        SyncOffAgain,
        SyncKept,
        SyncedPassword,
        DeleteSynced,
        DeleteUnsynced,
        Disable,
        Enable,
        PlainPassword,
    }

    fn sync_request(user: &str, on: i64) -> UpdateUserRequest {
        UpdateUserRequest {
            user_id: UserId::new(user),
            insert_attributes: vec![Attribute {
                name: "kerberossync".into(),
                value: on.into(),
            }],
            ..Default::default()
        }
    }

    async fn live(
        handler: &SqlBackendHandler,
        step: Life,
        disabled: GroupId,
    ) -> (UserId, std::result::Result<(), String>) {
        use lldap_domain_handlers::password::{
            PASSWORD_MIN_LENGTH, PasswordSync, change_password_everywhere,
        };
        let create = |on: i64| CreateUserRequest {
            user_id: UserId::new("erin"),
            email: "erin@example.com".into(),
            attributes: vec![Attribute {
                name: "kerberossync".into(),
                value: on.into(),
            }],
            ..Default::default()
        };
        let (user, done) = match step {
            Life::CreateSynced => ("erin", handler.create_user(create(1)).await),
            Life::CreateUnsynced => ("erin", handler.create_user(create(0)).await),
            Life::SyncOn => ("John", handler.update_user(sync_request("John", 1)).await),
            Life::SyncOff | Life::SyncOffAgain => {
                ("bob", handler.update_user(sync_request("bob", 0)).await)
            }
            Life::SyncKept => {
                let kept = sync_request("patrick", 1);
                ("patrick", handler.update_user(kept).await)
            }
            Life::SyncedPassword => {
                let patrick = UserId::new("patrick");
                let on = PasswordSync::On;
                let done = change_password_everywhere(
                    handler,
                    &patrick,
                    "Patrick-1",
                    on,
                    PASSWORD_MIN_LENGTH,
                );
                let done = done.await.map_err(|e| e.to_string());
                return (patrick, done);
            }
            Life::DeleteSynced => ("patrick", handler.delete_user(&"patrick".into()).await),
            Life::DeleteUnsynced => ("John", handler.delete_user(&"John".into()).await),
            Life::Disable => {
                let patrick = UserId::new("patrick");
                (
                    "patrick",
                    handler.add_user_to_group(&patrick, disabled).await,
                )
            }
            Life::Enable => {
                let patrick = UserId::new("patrick");
                let done = handler.remove_user_from_group(&patrick, disabled).await;
                ("patrick", done)
            }
            Life::PlainPassword => {
                let john = UserId::new("John");
                let off = PasswordSync::Off;
                let done = change_password_everywhere(
                    handler,
                    &john,
                    "John-Pass-1",
                    off,
                    PASSWORD_MIN_LENGTH,
                );
                let done = done.await.map_err(|e| e.to_string());
                return (john, done);
            }
        };
        (UserId::new(user), done.map_err(|e| e.to_string()))
    }

    #[tokio::test]
    #[serial]
    async fn test_each_life_step_with_kerberos_disabled_not_ready_or_unsettled() {
        use lldap_domain_handlers::kerberos::{
            ANSWER_UNSETTLED, CONFIRM_THE_DELETE, SYNC_OFF_FIRST, closed_to_writes,
        };
        use lldap_domain_handlers::password::realm_not_ready;
        use lldap_test_utils::recording_kerberos::{
            DEGRADED_CAUSE, DEGRADED_CLASS, DegradedGuard, NotReadyGuard,
        };
        use lldap_test_utils::recording_log::LogGuard;
        type Logged = (LogKind, bool, Option<String>);
        type Row = (Life, Option<String>, Option<bool>, Vec<Logged>);
        let left_as = |detail: &str| (LogKind::KerberosSync, true, Some(detail.to_owned()));
        let left = || left_as(LEFT_FOR_THE_START_PASS);
        let done = |kind| (kind, true, None);
        let failed = |kind, why: &str| (kind, false, Some(why.to_owned()));
        let (both_ways, sync_on) = (
            while_disabled(SYNC_OFF_FIRST),
            while_disabled(SYNC_ON_NEEDS_KERBEROS),
        );
        let create = CREATE_WITHOUT_SYNC.to_owned();
        let disabled: Vec<Row> = vec![
            (
                Life::CreateSynced,
                Some(create.clone()),
                None,
                vec![failed(LogKind::UserCreate, &create)],
            ),
            (
                Life::CreateUnsynced,
                None,
                Some(false),
                vec![done(LogKind::UserCreate)],
            ),
            (
                Life::SyncOn,
                Some(sync_on.clone()),
                Some(false),
                vec![failed(LogKind::UserUpdate, &sync_on)],
            ),
            (
                Life::SyncOff,
                None,
                Some(false),
                vec![done(LogKind::UserUpdate), left()],
            ),
            (
                Life::SyncOffAgain,
                None,
                Some(false),
                vec![done(LogKind::UserUpdate)],
            ),
            (
                Life::SyncedPassword,
                Some(both_ways.clone()),
                Some(true),
                vec![failed(LogKind::PasswordChange, &both_ways)],
            ),
            (
                Life::Disable,
                None,
                Some(true),
                vec![done(LogKind::MembershipAdd), left_as(STATUS_LEFT_DISABLED)],
            ),
            (
                Life::Enable,
                None,
                Some(true),
                vec![
                    done(LogKind::MembershipRemove),
                    left_as(STATUS_LEFT_DISABLED),
                ],
            ),
            (
                Life::PlainPassword,
                None,
                Some(false),
                vec![done(LogKind::PasswordChange)],
            ),
            (
                Life::DeleteSynced,
                None,
                None,
                vec![done(LogKind::UserDelete), left()],
            ),
            (
                Life::DeleteUnsynced,
                None,
                None,
                vec![done(LogKind::UserDelete)],
            ),
        ];
        let not_ready = |cause: &str| -> Vec<Row> {
            let password = realm_not_ready(cause).to_string();
            let refused = |step, after| (step, Some(cause.to_owned()), after, Vec::new());
            let membership = |step, kind| {
                let logged = vec![done(kind), left_as(STATUS_LEFT_NOT_READY)];
                (step, None, Some(true), logged)
            };
            let password_row = |step, after| {
                let logged = vec![failed(LogKind::PasswordChange, &password)];
                (step, Some(password.clone()), after, logged)
            };
            vec![
                refused(Life::CreateSynced, None),
                refused(Life::SyncOn, Some(false)),
                refused(Life::SyncOff, Some(true)),
                password_row(Life::SyncedPassword, Some(true)),
                membership(Life::Disable, LogKind::MembershipAdd),
                membership(Life::Enable, LogKind::MembershipRemove),
                password_row(Life::PlainPassword, Some(false)),
                refused(Life::DeleteSynced, Some(true)),
            ]
        };
        let unsettled = {
            let password = realm_not_ready(ANSWER_UNSETTLED).to_string();
            let again = format!("Kerberos KDC unavailable: {ANSWER_UNSETTLED}; try again");
            let refused = |step, kind, after| {
                let logged = vec![failed(kind, &again)];
                (step, Some(again.clone()), after, logged)
            };
            let password_row = |step, after| {
                let logged = vec![failed(LogKind::PasswordChange, &password)];
                (step, Some(password.clone()), after, logged)
            };
            let plain = |step, kind, after| (step, None, after, vec![done(kind)]);
            vec![
                refused(Life::CreateSynced, LogKind::UserCreate, None),
                plain(Life::CreateUnsynced, LogKind::UserCreate, Some(false)),
                refused(Life::SyncOn, LogKind::UserUpdate, Some(false)),
                refused(Life::SyncOff, LogKind::UserUpdate, Some(true)),
                password_row(Life::SyncedPassword, Some(true)),
                refused(Life::Disable, LogKind::MembershipAdd, Some(true)),
                refused(Life::Enable, LogKind::MembershipRemove, Some(true)),
                password_row(Life::PlainPassword, Some(false)),
                refused(Life::DeleteSynced, LogKind::UserDelete, Some(true)),
                plain(Life::DeleteUnsynced, LogKind::UserDelete, None),
            ]
        };
        let directory_only = {
            let unavailable = |cause: &str| format!("Kerberos KDC unavailable: {cause}");
            let told = unavailable(&closed_to_writes(DEGRADED_CLASS));
            let full = unavailable(DEGRADED_CAUSE);
            let refused = |step, kind, after| {
                let logged = vec![failed(kind, &full)];
                (step, Some(told.clone()), after, logged)
            };
            let membership = |step, kind| {
                let logged = vec![done(kind), left_as(STATUS_LEFT_DIRECTORY_ONLY)];
                (step, None, Some(true), logged)
            };
            let plain = |step, kind, after| (step, None, after, vec![done(kind)]);
            let synced_password = vec![failed(LogKind::PasswordChange, &full)];
            let confirm = |said: &str| format!("{said}; {CONFIRM_THE_DELETE}");
            let unconfirmed = vec![failed(LogKind::UserDelete, &confirm(&full))];
            vec![
                refused(Life::CreateSynced, LogKind::UserCreate, None),
                plain(Life::CreateUnsynced, LogKind::UserCreate, Some(false)),
                refused(Life::SyncOn, LogKind::UserUpdate, Some(false)),
                refused(Life::SyncOff, LogKind::UserUpdate, Some(true)),
                plain(Life::SyncKept, LogKind::UserUpdate, Some(true)),
                (
                    Life::SyncedPassword,
                    Some(told.clone()),
                    Some(true),
                    synced_password,
                ),
                membership(Life::Disable, LogKind::MembershipAdd),
                membership(Life::Enable, LogKind::MembershipRemove),
                plain(Life::PlainPassword, LogKind::PasswordChange, Some(false)),
                (
                    Life::DeleteSynced,
                    Some(confirm(&told)),
                    Some(true),
                    unconfirmed,
                ),
                plain(Life::DeleteUnsynced, LogKind::UserDelete, None),
            ]
        };
        let starting = "the Kerberos KDC is still starting; retry shortly";
        let states = [
            ("disabled", disabled),
            ("starting", not_ready(starting)),
            ("degraded", not_ready(DEGRADED_CAUSE)),
            ("directory-only", directory_only),
            ("unsettled", unsettled),
        ];
        for (state, rows) in states {
            let fixture = TestFixture::new().await;
            let accepting = RecordingGuard::install();
            for user in ["bob", "patrick"] {
                let on = sync_request(user, 1);
                fixture.handler.update_user(on).await.unwrap();
            }
            let disabled_group = insert_group(&fixture.handler, "lldap_disabled").await;
            drop(accepting);
            let _guards = (
                (state == "starting").then(NotReadyGuard::install),
                (state == "degraded").then(DegradedGuard::install),
                (state == "directory-only").then(DegradedGuard::install_directory_only),
                (state == "unsettled").then(|| RecordingGuard::install_unsettled(ANSWER_UNSETTLED)),
            );
            let log = LogGuard::install_on_this_thread();
            for (step, answer, after, logged) in rows {
                let (user, got) = live(&fixture.handler, step, disabled_group).await;
                let details = fixture.handler.get_user_details(&user).await;
                let synced = details.ok().map(|u| kerberos_sync_enabled(&u.attributes));
                let events: Vec<Logged> = log
                    .recorder()
                    .take_events()
                    .into_iter()
                    .filter(|e| e.target.as_deref() == Some(user.as_str()))
                    .map(|e| {
                        let shown = !e.success || e.kind == LogKind::KerberosSync;
                        (e.kind, e.success, e.detail.filter(|_| shown))
                    })
                    .collect();
                let public = state == "directory-only";
                let answered = match (&got, &answer) {
                    (Ok(()), None) => true,
                    (Err(e), Some(text)) if public => e == text && !e.contains(DEGRADED_CAUSE),
                    (Err(e), Some(text)) => e.contains(text.as_str()),
                    _ => false,
                };
                assert_eq!(
                    (answered, synced, events),
                    (true, after, logged),
                    "{state}, {step:?}: {got:?}"
                );
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_confirmed_delete_leaves_a_synced_users_principal_marked_in_directory_only() {
        use crate::sql_delete_marks::delete_marks;
        use lldap_test_utils::recording_kerberos::DegradedGuard;
        use lldap_test_utils::recording_log::LogGuard;
        type Logged = (LogKind, bool, Option<String>);
        type Row = (
            &'static str,
            &'static str,
            std::result::Result<Option<String>, String>,
            bool,
            Vec<Logged>,
            Vec<&'static str>,
        );
        let done = (LogKind::UserDelete, true, None);
        let left = |detail: &str| (LogKind::KerberosSync, true, Some(detail.to_owned()));
        let not_synced = (
            LogKind::UserDelete,
            false,
            Some(CONFIRMED_FOR_SYNC.to_owned()),
        );
        let rows: Vec<Row> = vec![
            (
                "directory-only",
                "patrick",
                Ok(Some(PRINCIPAL_STAYS.to_owned())),
                false,
                vec![done.clone(), left(LEFT_UNTIL_THE_REALM_OPENS)],
                vec!["patrick"],
            ),
            (
                "directory-only",
                "John",
                Err(format!("Internal error: `{CONFIRMED_FOR_SYNC}`")),
                true,
                vec![not_synced],
                vec![],
            ),
            (
                "disabled",
                "patrick",
                Ok(None),
                false,
                vec![done, left(LEFT_FOR_THE_START_PASS)],
                vec![],
            ),
        ];
        for (state, name, answer, kept, logged, marks) in rows {
            let fixture = TestFixture::new().await;
            let accepting = RecordingGuard::install();
            let on = sync_request("patrick", 1);
            fixture.handler.update_user(on).await.unwrap();
            drop(accepting);
            let _closed = (state == "directory-only").then(DegradedGuard::install_directory_only);
            let log = LogGuard::install_on_this_thread();
            let user = UserId::new(name);
            let got = fixture.handler.delete_user_confirmed(&user).await;
            let events: Vec<Logged> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.target.as_deref() == Some(user.as_str()))
                .map(|e| {
                    let shown = !e.success || e.kind == LogKind::KerberosSync;
                    (e.kind, e.success, e.detail.filter(|_| shown))
                })
                .collect();
            let there = fixture.handler.get_user_details(&user).await.is_ok();
            let marked = delete_marks(&fixture.handler.sql_pool).await.unwrap();
            let marks: Vec<String> = marks.into_iter().map(str::to_owned).collect();
            assert_eq!(
                (got.map_err(|e| e.to_string()), there, events, marked),
                (answer, kept, logged, marks),
                "{state}, {name}"
            );
        }

        let fixture = TestFixture::new().await;
        let _closed = DegradedGuard::install_directory_only();
        let raced = fixture
            .handler
            .delete_leaving_principal(&UserId::new("John"))
            .await;
        let marked = delete_marks(&fixture.handler.sql_pool).await.unwrap();
        let there = fixture.handler.get_user_details(&"John".into()).await;
        assert_eq!(
            (raced.map_err(|e| e.to_string()), marked, there.is_ok()),
            (
                Err(format!("Internal error: `{SYNC_CHANGED}`")),
                vec![],
                true
            ),
            "sync off when the transaction reads it again: nothing written, no mark"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_plain_write_in_directory_only_is_rolled_back_where_sync_is_on() {
        use lldap_opaque_handler::{OpaqueHandler, prepare_registration};
        use lldap_test_utils::recording_kerberos::DegradedGuard;
        use lldap_test_utils::recording_log::LogGuard;
        let fixture = TestFixture::new().await;
        let accepting = RecordingGuard::install();
        let on = sync_request("bob", 1);
        fixture.handler.update_user(on).await.unwrap();
        drop(accepting);
        let _closed = DegradedGuard::install_directory_only();
        let log = LogGuard::install_on_this_thread();
        let changed = format!("Internal error: `{SYNC_CHANGED}`");
        for (name, synced) in [("bob", true), ("John", false)] {
            let user = UserId::new(name);
            let (record, request) =
                prepare_registration(&fixture.handler, user.clone(), b"Plain-Pass-1")
                    .await
                    .unwrap();
            let finished = fixture.handler.registration_finish(request).await;
            let row = model::User::find_by_id(user.clone())
                .one(&fixture.handler.sql_pool)
                .await
                .unwrap();
            let stored = row.and_then(|row| row.password_hash) == Some(record);
            let deleted = fixture.handler.delete_with_sync_off(&user).await;
            let left = fixture.handler.get_user_details(&user).await.is_ok();
            let refusals: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| !e.success)
                .map(|e| (e.kind, e.detail))
                .collect();
            let got = (
                finished.map(drop).map_err(|e| e.to_string()),
                stored,
                deleted.map_err(|e| e.to_string()),
                left,
                refusals,
            );
            let want = match synced {
                true => (
                    Err(changed.clone()),
                    false,
                    Err(changed.clone()),
                    true,
                    vec![(LogKind::UserDelete, Some(SYNC_CHANGED.to_owned()))],
                ),
                false => (Ok(()), true, Ok(1), false, vec![]),
            };
            assert_eq!(got, want, "{name}, synced {synced}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_in_ready_lldap_disabled_and_the_principal_change_together_or_not_at_all() {
        use lldap_domain_handlers::kerberos::ANSWER_UNSETTLED;
        use lldap_test_utils::recording_log::LogGuard;
        type Logged = (LogKind, bool, Option<String>);
        type Row = (
            &'static str,
            Life,
            bool,
            Option<CommitError>,
            Option<String>,
            bool,
            Vec<Logged>,
        );
        let lost = || {
            Some(CommitError::Failed(
                "the database did not answer".to_owned(),
            ))
        };
        let why =
            |op: &str| format!("the {op} of user patrick failed: the database did not answer");
        let done = |kind| vec![(kind, true, None)];
        let failed = |kind, op| vec![(kind, false, Some(why(op)))];
        let again = format!("Kerberos KDC unavailable: {ANSWER_UNSETTLED}; try again");
        let rows: Vec<Row> = vec![
            (
                "lldap_disabled",
                Life::Disable,
                true,
                None,
                None,
                true,
                done(LogKind::MembershipAdd),
            ),
            (
                "lldap_disabled",
                Life::Enable,
                true,
                None,
                None,
                false,
                done(LogKind::MembershipRemove),
            ),
            (
                "lldap_disabled",
                Life::Disable,
                true,
                lost(),
                Some(why("disable")),
                false,
                failed(LogKind::MembershipAdd, "disable"),
            ),
            (
                "lldap_disabled",
                Life::Enable,
                true,
                lost(),
                Some(why("enable")),
                true,
                failed(LogKind::MembershipRemove, "enable"),
            ),
            (
                "lldap_disabled",
                Life::Disable,
                false,
                None,
                None,
                true,
                done(LogKind::MembershipAdd),
            ),
            (
                "lldap_disabled",
                Life::Disable,
                false,
                lost(),
                Some(why("disable")),
                false,
                failed(LogKind::MembershipAdd, "disable"),
            ),
            (
                "lldap_disabled",
                Life::Disable,
                false,
                Some(CommitError::Unsettled(ANSWER_UNSETTLED.to_owned())),
                Some(again.clone()),
                false,
                vec![(LogKind::MembershipAdd, false, Some(again.clone()))],
            ),
            (
                "LLDAP_Disabled",
                Life::Disable,
                true,
                None,
                None,
                true,
                done(LogKind::MembershipAdd),
            ),
            (
                "LLDAP_Disabled",
                Life::Enable,
                true,
                None,
                None,
                false,
                done(LogKind::MembershipRemove),
            ),
        ];
        for (name, step, synced, answer, refusal, member, logged) in rows {
            let fixture = TestFixture::new().await;
            let accepting = RecordingGuard::install();
            if synced {
                let on = sync_request("patrick", 1);
                fixture.handler.update_user(on).await.unwrap();
            }
            let group = insert_group(&fixture.handler, name).await;
            if matches!(step, Life::Enable) {
                let patrick = UserId::new("patrick");
                fixture
                    .handler
                    .add_user_to_group(&patrick, group)
                    .await
                    .unwrap();
            }
            drop(accepting);
            let guard = match answer {
                Some(e) => RecordingGuard::install_answering(Err(e)),
                None => RecordingGuard::install(),
            };
            let log = LogGuard::install_on_this_thread();
            let (_, got) = live(&fixture.handler, step, group).await;
            let filter = Some(UserRequestFilter::MemberOfId(group));
            let members = get_user_names(&fixture.handler, filter).await;
            let steps: Vec<_> = guard
                .recorder()
                .take_ops()
                .into_iter()
                .map(|op| match op {
                    KerberosOp::CommitUser { step, rows, .. } => (step, rows.len()),
                    _ => ("another call", 0),
                })
                .collect();
            let events: Vec<Logged> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.target.as_deref() == Some("patrick"))
                .map(|e| {
                    let shown = !e.success;
                    (e.kind, e.success, e.detail.filter(|_| shown))
                })
                .collect();
            let answered = match (&got, &refusal) {
                (Ok(()), None) => true,
                (Err(e), Some(text)) => e.contains(text.as_str()),
                _ => false,
            };
            let op = match step {
                Life::Disable => "disable",
                _ => "enable",
            };
            let one_change = vec![(op, 2)];
            assert_eq!(
                (
                    answered,
                    members.contains(&"patrick".to_owned()),
                    steps,
                    events
                ),
                (true, member, one_change, logged),
                "{name}, {step:?}, synced {synced}: {got:?}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_reset_without_kerberos_sets_the_password_and_turns_sync_off_together() {
        use lldap_domain_handlers::handler::{BindRequest, LoginHandler};
        let fixture = TestFixture::new().await;
        let bob = UserId::new("bob");
        let accepting = RecordingGuard::install();
        fixture
            .handler
            .update_user(sync_request("bob", 1))
            .await
            .unwrap();
        fixture
            .handler
            .ensure_kerberos_principal_consistency(&bob, true)
            .await
            .unwrap();
        drop(accepting);
        let row =
            |user: &str| logging::event(LogKind::KerberosSync, Some(user), true, Some("sync off"));
        let reset = fixture
            .handler
            .reset_password_without_sync(&bob, b"Bob-Reset-1", row("bob"))
            .await;
        let nobody = UserId::new("nobody");
        let gone = fixture
            .handler
            .reset_password_without_sync(&nobody, b"Nobody-Reset-1", row("nobody"))
            .await;
        let details = fixture.handler.get_user_details(&bob).await.unwrap();
        let bound = fixture
            .handler
            .bind(BindRequest {
                name: bob.clone(),
                password: "Bob-Reset-1".to_owned().into(),
            })
            .await;
        let rows = model::Logs::find()
            .count(&fixture.handler.sql_pool)
            .await
            .unwrap();
        assert_eq!(
            (
                reset.is_ok(),
                bound.is_ok(),
                kerberos_sync_enabled(&details.attributes),
                details.krb_principal_name,
                gone.is_err(),
                rows
            ),
            (true, true, false, None, true, 1),
            "the password, sync off and the row in one transaction; a user gone writes nothing"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_sync_on_is_refused_for_a_name_kerberos_refuses() {
        use lldap_test_utils::recording_log::LogGuard;
        let _guard = RecordingGuard::install();
        let fixture = TestFixture::new().await;
        let log = LogGuard::install_on_this_thread();
        let sync_on = || Attribute {
            name: "kerberossync".into(),
            value: 1i64.into(),
        };
        let rule = "Kerberos sync cannot be turned on for user jürgen: Kerberos username must \
                    be ASCII alphanumeric plus '.', '_' or '-'";
        let created = fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("jürgen"),
                email: "j@example.com".into(),
                attributes: vec![sync_on()],
                ..Default::default()
            })
            .await
            .unwrap_err();
        let absent = fixture
            .handler
            .get_user_details(&UserId::new("jürgen"))
            .await
            .is_err();
        assert_eq!(
            (created.to_string().contains(rule), absent),
            (true, true),
            "{created}"
        );

        insert_user_no_password(&fixture.handler, "jürgen").await;
        let updated = fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: UserId::new("jürgen"),
                insert_attributes: vec![sync_on()],
                ..Default::default()
            })
            .await
            .unwrap_err();
        let user = fixture
            .handler
            .get_user_details(&UserId::new("jürgen"))
            .await
            .unwrap();
        assert_eq!(
            (
                updated.to_string().contains(rule),
                kerberos_sync_enabled(&user.attributes)
            ),
            (true, false),
            "{updated}"
        );
        let rows: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.target.as_deref() == Some("jürgen") && !e.success)
            .map(|e| (e.kind, e.detail.as_deref() == Some(rule)))
            .collect();
        assert_eq!(
            rows,
            vec![(LogKind::UserCreate, true), (LogKind::UserUpdate, true)],
            "one failure row for each refusal"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_sync_on_at_create_is_refused_for_an_alias_name() {
        use lldap_test_utils::recording_log::LogGuard;
        let why = "the principal name of user carl is an alias of svc@RECORDER.TEST; remove \
                   that alias first (kadmin delprinc carl@RECORDER.TEST)";
        let _guard = RecordingGuard::install_aliased(why);
        let fixture = TestFixture::new().await;
        let log = LogGuard::install_on_this_thread();
        let request = |sync: i64| CreateUserRequest {
            user_id: UserId::new("carl"),
            email: "carl@example.com".into(),
            attributes: vec![Attribute {
                name: "kerberossync".into(),
                value: sync.into(),
            }],
            ..Default::default()
        };
        let created = fixture.handler.create_user(request(1)).await.unwrap_err();
        let absent = fixture
            .handler
            .get_user_details(&UserId::new("carl"))
            .await
            .is_err();
        let rows: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.target.as_deref() == Some("carl"))
            .map(|e| (e.kind, e.success, e.detail))
            .collect();
        let sentence = format!("Kerberos sync cannot be turned on for user carl: {why}");
        assert_eq!(
            (created.to_string().contains(&sentence), absent, rows),
            (
                true,
                true,
                vec![(LogKind::UserCreate, false, Some(sentence.clone()))]
            ),
            "{created}"
        );
        fixture.handler.create_user(request(0)).await.unwrap();
    }

    #[test]
    fn test_the_admin_and_disabled_groups_are_named_in_any_case() {
        let rows = [
            ("lldap_admin", true, false),
            ("LLDAP_Admin", true, false),
            ("lldap_disabled", false, true),
            ("LLDAP_DISABLED", false, true),
            ("lldap_admins", false, false),
            ("lldap_mfa_disabled", false, false),
        ];
        for (name, admin, disabled) in rows {
            assert_eq!(
                (is_admin_group(name), is_disabled_group(name)),
                (admin, disabled),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn test_last_lldap_admin_cannot_be_removed_or_deleted() {
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
            "expected last-admin protection, got: {err}"
        );
        let still_member = fixture
            .handler
            .list_users(Some(UserRequestFilter::MemberOfId(admin_gid)), false)
            .await
            .unwrap();
        assert_eq!(still_member.len(), 1);

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
    async fn test_user_writes_that_can_move_an_ou_swap_the_policy_cache() {
        let fixture = TestFixture::new().await;
        let handler = &fixture.handler;
        let bob = UserId::new("bob");
        let ou = |value: &str| Attribute {
            name: "ou".into(),
            value: value.to_owned().into(),
        };
        let mut seen = handler.policy_changes();
        let mut swapped = || {
            let now = handler.policy_changes();
            let changed = now - seen;
            seen = now;
            changed
        };
        let update = |request: UpdateUserRequest| UpdateUserRequest {
            user_id: bob.clone(),
            ..request
        };
        handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("dave"),
                email: "dave@example.com".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(swapped(), 1, "create");
        let rows = [
            (
                "display name",
                update(UpdateUserRequest {
                    display_name: Some("Bob".to_owned()),
                    ..Default::default()
                }),
                0,
            ),
            (
                "ou set",
                update(UpdateUserRequest {
                    insert_attributes: vec![ou("people\\labs")],
                    ..Default::default()
                }),
                1,
            ),
            (
                "ou removed",
                update(UpdateUserRequest {
                    delete_attributes: vec!["OU".into()],
                    ..Default::default()
                }),
                1,
            ),
        ];
        for (row, request, expected) in rows {
            handler.update_user(request).await.unwrap();
            assert_eq!(swapped(), expected, "{row}");
        }
        handler.delete_user(&UserId::new("dave")).await.unwrap();
        assert_eq!(swapped(), 1, "delete");
        handler.delete_user(&UserId::new("dave")).await.unwrap_err();
        assert_eq!(swapped(), 0, "no such user");
    }
}
