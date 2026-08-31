use crate::sql_backend_handler::{
    SqlBackendHandler, attribute_value_to_db_bytes, bool_to_expr, describe_changes,
    get_repeated_filter, is_backend_writable_readonly_attribute,
};
use async_trait::async_trait;
use lldap_domain::{
    requests::{CreateGroupRequest, UpdateGroupRequest},
    types::{
        Attribute, AttributeName, AttributeValue, Cardinality, Group, GroupDetails, GroupId,
        Serialized, UserId, Uuid,
    },
};
use lldap_domain_handlers::handler::{
    GroupBackendHandler, GroupListerBackendHandler, GroupRequestFilter, ReadSchemaBackendHandler,
    SubStringFilter, SystemConfigBackendHandler,
};
use lldap_domain_handlers::kerberos::require_kdc_ready;
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_domain_handlers::mfa::is_protected_group;
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, GroupColumn, MembershipColumn, codec},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, Set, TransactionTrait,
    sea_query::{Alias, Cond, Expr, Func, IntoCondition, OnConflict, SimpleExpr},
};
use tracing::instrument;

fn attribute_condition(name: AttributeName, value: Option<&AttributeValue>) -> Cond {
    Expr::in_subquery(
        Expr::col(GroupColumn::GroupId.as_column_ref()),
        model::GroupAttributes::find()
            .select_only()
            .column(model::GroupAttributesColumn::GroupId)
            .filter(model::GroupAttributesColumn::AttributeName.eq(name))
            .filter(
                value
                    .map(|v| model::GroupAttributesColumn::Value.eq(attribute_value_to_db_bytes(v)))
                    .unwrap_or_else(|| SimpleExpr::Constant(true.into())),
            )
            .into_query(),
    )
    .into_condition()
}

fn attribute_substring_condition(name: AttributeName, filter: &SubStringFilter) -> Cond {
    let like_pattern = filter.to_sql_filter();
    Expr::in_subquery(
        Expr::col(GroupColumn::GroupId.as_column_ref()),
        model::GroupAttributes::find()
            .select_only()
            .column(model::GroupAttributesColumn::GroupId)
            .filter(model::GroupAttributesColumn::AttributeName.eq(name.clone()))
            .filter(
                SimpleExpr::FunctionCall(Func::lower(Expr::col(
                    model::GroupAttributesColumn::Value,
                )))
                .like(like_pattern),
            )
            .into_query(),
    )
    .into_condition()
}

fn get_group_filter_expr(filter: GroupRequestFilter) -> Cond {
    use GroupRequestFilter::*;
    let group_table = Alias::new("groups");
    match filter {
        True => bool_to_expr(true),
        False => bool_to_expr(false),
        And(fs) => get_repeated_filter(fs, Cond::all(), true, get_group_filter_expr),
        Or(fs) => get_repeated_filter(fs, Cond::any(), false, get_group_filter_expr),
        Not(f) => get_group_filter_expr(*f).not(),
        DisplayName(name) => GroupColumn::LowercaseDisplayName
            .eq(name.as_str().to_lowercase())
            .into_condition(),
        GroupId(id) => GroupColumn::GroupId.eq(id.0).into_condition(),
        Uuid(uuid) => GroupColumn::Uuid.eq(uuid.to_string()).into_condition(),
        Member(user) => GroupColumn::GroupId
            .in_subquery(
                model::Membership::find()
                    .select_only()
                    .column(MembershipColumn::GroupId)
                    .filter(MembershipColumn::UserId.eq(user))
                    .into_query(),
            )
            .into_condition(),
        DisplayNameSubString(filter) => SimpleExpr::FunctionCall(Func::lower(Expr::col((
            group_table,
            GroupColumn::LowercaseDisplayName,
        ))))
        .like(filter.to_sql_filter())
        .into_condition(),
        AttributeEquality(name, value) => attribute_condition(name, Some(&value)),
        CustomAttributePresent(name) => attribute_condition(name, None),

        GreaterOrEqual(column, value) => {
            let col = column.to_ascii_lowercase();
            match col.as_str() {
                "creationdate" => {
                    // A table alias, or the filter is ambiguous inside find_also_linked's join.
                    Expr::col((group_table.clone(), GroupColumn::CreationDate))
                        .gte(value)
                        .into_condition()
                }
                "modifieddate" => Expr::col((group_table.clone(), GroupColumn::ModifiedDate))
                    .gte(value)
                    .into_condition(),
                _ => {
                    tracing::warn!(
                        "GreaterOrEqual filter received on unsupported group column: {}. Returning no results.",
                        column
                    );
                    bool_to_expr(false) // Safe: matches nothing
                }
            }
        }

        LessOrEqual(column, value) => {
            let col = column.to_ascii_lowercase();
            match col.as_str() {
                "creationdate" => Expr::col((group_table.clone(), GroupColumn::CreationDate))
                    .lte(value)
                    .into_condition(),
                "modifieddate" => Expr::col((group_table.clone(), GroupColumn::ModifiedDate))
                    .lte(value)
                    .into_condition(),
                _ => {
                    tracing::warn!(
                        "LessOrEqual filter received on unsupported group column: {}. Returning no results.",
                        column
                    );
                    bool_to_expr(false)
                }
            }
        }
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

#[async_trait]
impl GroupListerBackendHandler for SqlBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn list_groups(&self, filters: Option<GroupRequestFilter>) -> Result<Vec<Group>> {
        let filters = filters
            .map(|f| {
                GroupColumn::GroupId
                    .in_subquery(
                        model::Group::find()
                            .find_also_linked(model::memberships::GroupToUser)
                            .select_only()
                            .column(GroupColumn::GroupId)
                            .filter(get_group_filter_expr(f))
                            .into_query(),
                    )
                    .into_condition()
            })
            .unwrap_or_else(|| SimpleExpr::Value(true.into()).into_condition());
        let results = model::Group::find()
            .order_by_asc(GroupColumn::GroupId)
            .find_with_related(model::Membership)
            .filter(filters.clone())
            .all(&self.sql_pool)
            .await?;
        let all_user_ids: Vec<UserId> = results
            .iter()
            .flat_map(|(_, memberships)| memberships.iter().map(|m| m.user_id.clone()))
            .collect();

        let member_ous: std::collections::HashMap<UserId, String> = if all_user_ids.is_empty() {
            std::collections::HashMap::new()
        } else {
            let ou_attrs = model::UserAttributes::find()
                .filter(model::UserAttributesColumn::UserId.is_in(all_user_ids.clone()))
                .filter(model::UserAttributesColumn::AttributeName.eq("ou"))
                .all(&self.sql_pool)
                .await?;

            ou_attrs
                .into_iter()
                .filter_map(|attr| {
                    String::from_utf8(attr.value.0.clone())
                        .ok()
                        .map(|ou| (attr.user_id, ou))
                })
                .collect()
        };

        let mut groups: Vec<_> = results
            .into_iter()
            .map(|(group, memberships)| {
                use std::collections::BTreeSet;

                let mut seen = BTreeSet::new();
                let mut unique_users = Vec::new();

                for m in memberships {
                    if seen.insert(m.user_id.clone()) {
                        let ou = member_ous
                            .get(&m.user_id)
                            .cloned()
                            .unwrap_or_else(|| "people".to_string());

                        unique_users.push(lldap_domain::types::GroupMember {
                            user_id: m.user_id,
                            ou,
                        });
                    }
                }

                Group {
                    users: unique_users,
                    ..group.into()
                }
            })
            .collect();
        // TODO: should be wrapped in a transaction
        let schema = self.get_schema().await?;
        let attributes = model::GroupAttributes::find()
            .filter(
                model::GroupAttributesColumn::GroupId.in_subquery(
                    model::Group::find()
                        .filter(filters)
                        .select_only()
                        .column(model::groups::Column::GroupId)
                        .into_query(),
                ),
            )
            .order_by_asc(model::GroupAttributesColumn::GroupId)
            .order_by_asc(model::GroupAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;
        let mut attributes_iter = attributes.into_iter().peekable();
        use itertools::Itertools;
        for group in groups.iter_mut() {
            let mut attrs: Vec<_> = attributes_iter
                .take_while_ref(|u| u.group_id == group.id)
                .map(|a| {
                    codec::decode_attribute(a.attribute_name, &a.value, schema.group_attributes())
                })
                .collect::<Result<Vec<_>>>()?;

            for attr in &mut attrs {
                attr.name =
                    SqlBackendHandler::canonical_group_attribute_name(&schema, attr.name.as_str());
            }
            group.attributes = attrs;
        }
        groups.sort_by(|g1, g2| g1.display_name.cmp(&g2.display_name));
        Ok(groups)
    }
}

#[async_trait]
impl GroupBackendHandler for SqlBackendHandler {
    #[instrument(skip(self), level = "debug", ret, err)]
    async fn get_group_details(&self, group_id: GroupId) -> Result<GroupDetails> {
        let mut group_details = model::Group::find_by_id(group_id)
            .one(&self.sql_pool)
            .await?
            .map(Into::<GroupDetails>::into)
            .ok_or_else(|| DomainError::EntityNotFound(format!("{group_id:?}")))?;
        let attributes = model::GroupAttributes::find()
            .filter(model::GroupAttributesColumn::GroupId.eq(group_details.group_id))
            .order_by_asc(model::GroupAttributesColumn::AttributeName)
            .all(&self.sql_pool)
            .await?;
        let schema = self.get_schema().await?;
        group_details.attributes = attributes
            .into_iter()
            .map(|a| {
                let mut attr =
                    codec::decode_attribute(a.attribute_name, &a.value, schema.group_attributes())?;

                attr.name =
                    SqlBackendHandler::canonical_group_attribute_name(&schema, attr.name.as_str());
                Ok(attr)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(group_details)
    }

    #[instrument(skip(self), level = "debug", err, fields(group_id = ?request.group_id))]
    async fn update_group(&self, request: UpdateGroupRequest) -> Result<()> {
        require_kdc_ready()?;
        let current_name = model::Group::find_by_id(request.group_id)
            .select_only()
            .column(GroupColumn::DisplayName)
            .into_tuple::<(String,)>()
            .one(&self.sql_pool)
            .await?
            .map(|(name,)| name)
            .ok_or_else(|| {
                DomainError::EntityNotFound(format!("No such group: '{:?}'", request.group_id))
            })?;
        if request.display_name.is_some() && is_protected_group(&current_name, self.mfa_policy) {
            return Err(DomainError::InternalError(format!(
                "Cannot rename built-in group '{current_name}'"
            )));
        }
        let changes = describe_changes(
            &request.insert_attributes,
            &request.delete_attributes,
            &[("display_name", request.display_name.is_some())],
        );

        self.sql_pool
            .transaction::<_, (), DomainError>(|transaction| {
                Box::pin(
                    async move { Self::update_group_with_transaction(request, transaction).await },
                )
            })
            .await?;
        logging::record(LogKind::GroupUpdate, Some(&current_name), Some(&changes));
        Ok(())
    }

    #[instrument(skip(self), level = "debug", ret, err)]
    async fn create_group(&self, request: CreateGroupRequest) -> Result<GroupId> {
        require_kdc_ready()?;
        let now = chrono::Utc::now().naive_utc();
        let uuid = Uuid::from_name_and_date(request.display_name.as_str(), &now);
        let display_name = request.display_name.as_str().to_owned();
        let lower_display_name = display_name.to_lowercase();

        let new_group = model::groups::ActiveModel {
            display_name: Set(request.display_name),
            lowercase_display_name: Set(lower_display_name),
            creation_date: Set(now),
            uuid: Set(uuid),
            modified_date: Set(now),
            ..Default::default()
        };

        let allowed_ous = self.get_allowed_ous().await?;
        let default_ou = allowed_ous
            .into_iter()
            .next()
            .unwrap_or_else(|| "groups".to_string());

        let group_id = self
            .sql_pool
            .transaction::<_, GroupId, DomainError>(|transaction| {
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
                    Self::validate_group_posix_numbers(transaction, &posix_numbers, None).await?;

                    let mut final_attributes = request.attributes;

                    if !final_attributes.iter().any(|a| a.name.as_str() == "ou") {
                        final_attributes.push(Attribute {
                            name: "ou".into(),
                            value: AttributeValue::String(Cardinality::Singleton(default_ou)),
                        });
                    }

                    if settings.group_gidnumber_assign {
                        let already_has_gid = final_attributes
                            .iter()
                            .any(|a| a.name.as_str() == "gidnumber");
                        if !already_has_gid {
                            let next_gid = Self::next_available_gid_number(
                                transaction,
                                settings.group_gidnumber_start,
                                settings.group_gidnumber_max,
                            )
                            .await?;
                            final_attributes.push(Attribute {
                                name: "gidnumber".into(),
                                value: AttributeValue::Integer(Cardinality::Singleton(next_gid)),
                            });
                        }
                    }

                    let group_id = new_group.insert(transaction).await?.group_id;
                    let mut new_group_attributes = Vec::new();

                    for attribute in final_attributes {
                        let canonical_name = schema
                            .group_attributes()
                            .get_by_name_or_alias(attribute.name.as_str())
                            .map(|s| s.name.clone().into())
                            .unwrap_or_else(|| attribute.name.clone());
                        let attr_name = attribute.name.as_str();

                        if schema
                            .group_attributes()
                            .get_attribute_type(attr_name)
                            .is_some()
                            || is_backend_writable_readonly_attribute(attr_name)
                        {
                            let db_value = attribute_value_to_db_bytes(&attribute.value);
                            new_group_attributes.push(model::group_attributes::ActiveModel {
                                group_id: Set(group_id),
                                attribute_name: Set(canonical_name),
                                value: Set(Serialized(db_value)),
                            });
                        } else {
                            return Err(DomainError::InternalError(format!(
                                "Group attribute name {} doesn't exist in the schema",
                                attribute.name
                            )));
                        }
                    }

                    if !new_group_attributes.is_empty() {
                        model::GroupAttributes::insert_many(new_group_attributes)
                            .exec(transaction)
                            .await?;
                    }
                    Ok(group_id)
                })
            })
            .await?;
        logging::record(LogKind::GroupCreate, Some(&display_name), None);
        Ok(group_id)
    }

    #[instrument(skip(self), level = "debug", err)]
    async fn delete_group(&self, group_id: GroupId) -> Result<()> {
        require_kdc_ready()?;
        let group_details = self.get_group_details(group_id).await?;

        if is_protected_group(group_details.display_name.as_str(), self.mfa_policy) {
            return Err(DomainError::InternalError(format!(
                "Cannot delete built-in group '{}'",
                group_details.display_name
            )));
        }

        let res = model::Group::delete_by_id(group_id)
            .exec(&self.sql_pool)
            .await?;
        if res.rows_affected == 0 {
            return Err(DomainError::EntityNotFound(format!(
                "No such group: '{group_id:?}'"
            )));
        }
        logging::record(
            LogKind::GroupDelete,
            Some(group_details.display_name.as_str()),
            None,
        );
        Ok(())
    }
}

impl SqlBackendHandler {
    async fn update_group_with_transaction(
        request: UpdateGroupRequest,
        transaction: &DatabaseTransaction,
    ) -> Result<()> {
        let lower_display_name = request
            .display_name
            .as_ref()
            .map(|s| s.as_str().to_lowercase());
        let now = chrono::Utc::now().naive_utc();
        let update_group = model::groups::ActiveModel {
            group_id: Set(request.group_id),
            display_name: request.display_name.map(Set).unwrap_or_default(),
            lowercase_display_name: lower_display_name.map(Set).unwrap_or_default(),
            modified_date: Set(now),
            ..Default::default()
        };
        update_group.update(transaction).await?;

        let schema = Self::get_schema_with_transaction(transaction).await?;

        let posix_numbers: Vec<(String, i64)> = request
            .insert_attributes
            .iter()
            .filter_map(|attr| match &attr.value {
                AttributeValue::Integer(Cardinality::Singleton(value)) if *value != 0 => {
                    Some((attr.name.as_str().to_owned(), *value))
                }
                _ => None,
            })
            .collect();
        Self::validate_group_posix_numbers(transaction, &posix_numbers, Some(request.group_id))
            .await?;

        let mut update_group_attributes = Vec::new();
        let mut remove_group_attributes = Vec::new();

        for attribute in request.insert_attributes {
            let canonical_name = schema
                .group_attributes()
                .get_by_name_or_alias(attribute.name.as_str())
                .map(|s| s.name.clone().into())
                .unwrap_or_else(|| attribute.name.clone());
            update_group_attributes.push(model::group_attributes::ActiveModel {
                group_id: Set(request.group_id),
                attribute_name: Set(canonical_name),
                value: Set(Serialized(attribute_value_to_db_bytes(&attribute.value))),
            });
        }

        for attribute in request.delete_attributes {
            let canonical_name: AttributeName = schema
                .group_attributes()
                .get_by_name_or_alias(attribute.as_str())
                .map(|s| s.name.clone().into())
                .unwrap_or_else(|| attribute.clone());
            let attr_name = attribute.as_str();

            if schema
                .group_attributes()
                .get_attribute_type(attr_name)
                .is_some()
                || is_backend_writable_readonly_attribute(attr_name)
            {
                remove_group_attributes.push(canonical_name);
            } else {
                return Err(DomainError::InternalError(format!(
                    "Group attribute name {} doesn't exist in the schema, yet was attempted to be removed from the database",
                    attr_name
                )));
            }
        }

        if !remove_group_attributes.is_empty() {
            model::GroupAttributes::delete_many()
                .filter(model::GroupAttributesColumn::GroupId.eq(request.group_id))
                .filter(model::GroupAttributesColumn::AttributeName.is_in(remove_group_attributes))
                .exec(transaction)
                .await?;
        }
        if !update_group_attributes.is_empty() {
            model::GroupAttributes::insert_many(update_group_attributes)
                .on_conflict(
                    OnConflict::columns([
                        model::GroupAttributesColumn::GroupId,
                        model::GroupAttributesColumn::AttributeName,
                    ])
                    .update_column(model::GroupAttributesColumn::Value)
                    .to_owned(),
                )
                .exec(transaction)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::*;
    use lldap_domain::{
        requests::CreateAttributeRequest,
        types::{Attribute, AttributeType, GroupName, UserId},
    };
    use lldap_domain_handlers::handler::{SchemaBackendHandler, SubStringFilter};
    use pretty_assertions::assert_eq;

    async fn get_group_ids(
        handler: &SqlBackendHandler,
        filters: Option<GroupRequestFilter>,
    ) -> Vec<GroupId> {
        handler
            .list_groups(filters)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.id)
            .collect::<Vec<_>>()
    }

    async fn get_group_names(
        handler: &SqlBackendHandler,
        filters: Option<GroupRequestFilter>,
    ) -> Vec<GroupName> {
        handler
            .list_groups(filters)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.display_name)
            .collect::<Vec<_>>()
    }

    #[tokio::test]
    async fn test_list_groups_no_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_names(&fixture.handler, None).await,
            vec![
                "Best Group".into(),
                "Empty Group".into(),
                "Worst Group".into()
            ]
        );
    }

    #[tokio::test]
    async fn test_list_groups_simple_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_names(
                &fixture.handler,
                Some(GroupRequestFilter::Or(vec![
                    GroupRequestFilter::DisplayName("Empty Group".into()),
                    GroupRequestFilter::Member(UserId::new("bob")),
                ]))
            )
            .await,
            vec!["Best Group".into(), "Empty Group".into()]
        );
    }

    #[tokio::test]
    async fn test_list_groups_case_insensitive_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_names(
                &fixture.handler,
                Some(GroupRequestFilter::DisplayName("eMpTy gRoup".into()),)
            )
            .await,
            vec!["Empty Group".into()]
        );
    }

    #[tokio::test]
    async fn test_list_groups_negation() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_ids(
                &fixture.handler,
                Some(GroupRequestFilter::And(vec![
                    GroupRequestFilter::Not(Box::new(GroupRequestFilter::DisplayName(
                        "value".into()
                    ))),
                    GroupRequestFilter::GroupId(fixture.groups[0]),
                ]))
            )
            .await,
            vec![fixture.groups[0]]
        );
    }

    #[tokio::test]
    async fn test_list_groups_substring_filter() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_ids(
                &fixture.handler,
                Some(GroupRequestFilter::DisplayNameSubString(SubStringFilter {
                    initial: Some("be".to_owned()),
                    any: vec!["sT".to_owned()],
                    final_: Some("P".to_owned()),
                })),
            )
            .await,
            vec![fixture.groups[0]]
        );
    }

    #[tokio::test]
    async fn test_list_groups_other_filter() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .add_group_attribute(CreateAttributeRequest {
                name: "gid".into(),
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: true,
                is_editable: true,
            })
            .await
            .unwrap();
        fixture
            .handler
            .update_group(UpdateGroupRequest {
                group_id: fixture.groups[0],
                display_name: None,
                delete_attributes: Vec::new(),
                insert_attributes: vec![Attribute {
                    name: "gid".into(),
                    value: 512.into(),
                }],
            })
            .await
            .unwrap();
        assert_eq!(
            get_group_ids(
                &fixture.handler,
                Some(GroupRequestFilter::AttributeEquality(
                    AttributeName::from("gid"),
                    512.into(),
                )),
            )
            .await,
            vec![fixture.groups[0]]
        );
    }

    #[tokio::test]
    async fn test_get_group_details() {
        let fixture = TestFixture::new().await;
        let details = fixture
            .handler
            .get_group_details(fixture.groups[0])
            .await
            .unwrap();
        assert_eq!(details.group_id, fixture.groups[0]);
        assert_eq!(details.display_name, "Best Group".into());
        assert_eq!(
            get_group_ids(
                &fixture.handler,
                Some(GroupRequestFilter::Uuid(details.uuid))
            )
            .await,
            vec![fixture.groups[0]]
        );
    }

    #[tokio::test]
    async fn test_update_group() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .update_group(UpdateGroupRequest {
                group_id: fixture.groups[0],
                display_name: Some("Awesomest Group".into()),
                delete_attributes: Vec::new(),
                insert_attributes: Vec::new(),
            })
            .await
            .unwrap();
        let details = fixture
            .handler
            .get_group_details(fixture.groups[0])
            .await
            .unwrap();
        assert_eq!(details.display_name, "Awesomest Group".into());
    }

    #[tokio::test]
    async fn test_delete_group() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            get_group_ids(&fixture.handler, None).await,
            vec![fixture.groups[0], fixture.groups[2], fixture.groups[1]]
        );
        fixture
            .handler
            .delete_group(fixture.groups[0])
            .await
            .unwrap();
        assert_eq!(
            get_group_ids(&fixture.handler, None).await,
            vec![fixture.groups[2], fixture.groups[1]]
        );
    }

    #[tokio::test]
    async fn test_create_group() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .add_group_attribute(CreateAttributeRequest {
                name: "new_attribute".into(),
                attribute_type: AttributeType::String,
                is_list: false,
                is_visible: true,
                is_editable: true,
            })
            .await
            .unwrap();

        let new_group_id = fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "New Group".into(),
                attributes: vec![Attribute {
                    name: "new_attribute".into(),
                    value: "value".to_string().into(),
                }],
            })
            .await
            .unwrap();

        let group_details = fixture
            .handler
            .get_group_details(new_group_id)
            .await
            .unwrap();

        assert_eq!(group_details.display_name, "New Group".into());

        assert_eq!(
            group_details.attributes,
            vec![
                Attribute {
                    name: "new_attribute".into(),
                    value: "value".to_string().into(),
                },
                Attribute {
                    name: "ou".into(),
                    value: "people".to_string().into(), // default from allowed_ous
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_set_group_attributes() {
        let fixture = TestFixture::new().await;

        fixture
            .handler
            .add_group_attribute(CreateAttributeRequest {
                name: "new_attribute".into(),
                attribute_type: AttributeType::Integer,
                is_list: false,
                is_visible: true,
                is_editable: true,
            })
            .await
            .unwrap();

        let group_id = fixture.groups[0];

        let attributes = vec![Attribute {
            name: "new_attribute".into(),
            value: 42i64.into(),
        }];

        fixture
            .handler
            .update_group(UpdateGroupRequest {
                group_id,
                display_name: None,
                delete_attributes: Vec::new(),
                insert_attributes: attributes.clone(),
            })
            .await
            .unwrap();

        let details = fixture.handler.get_group_details(group_id).await.unwrap();

        assert!(
            details
                .attributes
                .iter()
                .any(|a| a.name.as_str() == "new_attribute" && a.value == 42i64.into())
        );
        assert!(details.attributes.iter().any(|a| a.name.as_str() == "ou"));

        fixture
            .handler
            .update_group(UpdateGroupRequest {
                group_id,
                display_name: None,
                delete_attributes: vec!["new_attribute".into()],
                insert_attributes: Vec::new(),
            })
            .await
            .unwrap();

        let details = fixture.handler.get_group_details(group_id).await.unwrap();
        assert!(
            !details
                .attributes
                .iter()
                .any(|a| a.name.as_str() == "new_attribute")
        );
        assert!(details.attributes.iter().any(|a| a.name.as_str() == "ou")); // ou is protected
    }

    #[tokio::test]
    async fn test_create_group_duplicate_name() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "New Group".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "neW group".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn test_builtin_group_protection() {
        let fixture = TestFixture::new().await;
        let create = |name: &str| {
            fixture.handler.create_group(CreateGroupRequest {
                display_name: name.into(),
                ..Default::default()
            })
        };
        let rename = |group_id, name: &str| {
            fixture.handler.update_group(UpdateGroupRequest {
                group_id,
                display_name: Some(name.into()),
                delete_attributes: vec![],
                insert_attributes: vec![],
            })
        };

        let sudohost = create("lldap_sudohost").await.unwrap();
        let err = fixture.handler.delete_group(sudohost).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("built-in group") || msg.contains("Cannot delete"),
            "expected built-in delete protection, got: {msg}"
        );
        let password_manager = create("lldap_password_manager").await.unwrap();
        let err = rename(password_manager, "renamed-pm").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("built-in group") || msg.contains("Cannot rename"),
            "expected built-in rename protection, got: {msg}"
        );

        let custom = create("my-custom-group").await.unwrap();
        rename(custom, "my-custom-renamed").await.unwrap();
        let details = fixture.handler.get_group_details(custom).await.unwrap();
        assert_eq!(details.display_name.as_str(), "my-custom-renamed");
        fixture.handler.delete_group(custom).await.unwrap();
    }
}
