use crate::sql_backend_handler::SqlBackendHandler;
use async_trait::async_trait;
use lldap_domain::types::{
    Attribute, AttributeName, AttributeValue, Cardinality, GroupId, Serialized, UserId,
};
use lldap_domain_handlers::handler::{
    PosixBackendHandler, PosixSettings, SystemConfigBackendHandler,
};
use lldap_domain_handlers::kerberos::require_kdc_ready;
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, system_config},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait, sea_query::query::OnConflict,
};
use tracing::instrument;

#[async_trait]
impl PosixBackendHandler for SqlBackendHandler {
    async fn get_posix_settings(&self) -> Result<PosixSettings> {
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

    async fn set_posix_settings(&self, settings: PosixSettings) -> Result<()> {
        require_kdc_ready()?;
        let json = serde_json::to_string(&settings).map_err(|e| {
            DomainError::InternalError(format!("Failed to serialize posix_settings: {}", e))
        })?;
        self.set_system_config("posix_settings", json).await
    }

    #[instrument(skip(self), level = "info", err)]
    async fn reassign_gid_numbers(&self) -> Result<()> {
        require_kdc_ready()?;
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
        logging::record(
            LogKind::PosixChange,
            Some("group gidnumber"),
            Some("reassign"),
        );
        Ok(())
    }

    #[instrument(skip(self), level = "info", err)]
    async fn reassign_user_uid_numbers(&self) -> Result<()> {
        require_kdc_ready()?;
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
                            posix_upsert_user_attribute(
                                tx,
                                user.user_id,
                                "uidnumber",
                                next.to_string().into_bytes(),
                            )
                            .await?;
                        }
                    } else {
                        posix_clear_user_attribute(tx, "uidnumber").await?;
                    }
                    Ok(())
                })
            })
            .await?;
        logging::record(
            LogKind::PosixChange,
            Some("user uidnumber"),
            Some("reassign"),
        );
        Ok(())
    }

    #[instrument(skip(self), level = "info", err)]
    async fn reassign_user_gid_numbers(&self) -> Result<()> {
        require_kdc_ready()?;
        let settings = self.get_posix_settings().await?;
        self.sql_pool
            .transaction::<_, (), DomainError>(|tx| {
                Box::pin(async move {
                    if settings.user_gidnumber_assign {
                        // Static assignment: every user gets the same gidNumber from config.
                        let users = model::User::find().all(tx).await?;
                        for user in users {
                            posix_upsert_user_attribute(
                                tx,
                                user.user_id,
                                "gidnumber",
                                settings.user_gidnumber_start.to_string().into_bytes(),
                            )
                            .await?;
                        }
                    } else {
                        posix_clear_user_attribute(tx, "gidnumber").await?;
                    }
                    Ok(())
                })
            })
            .await?;
        logging::record(
            LogKind::PosixChange,
            Some("user gidnumber"),
            Some("reassign"),
        );
        Ok(())
    }

    #[instrument(skip(self), level = "info", err)]
    async fn reassign_user_homedirectories(&self) -> Result<()> {
        require_kdc_ready()?;
        let settings = self.get_posix_settings().await?;
        self.sql_pool
            .transaction::<_, (), DomainError>(|tx| {
                Box::pin(async move {
                    if settings.user_homedirectory_assign {
                        let users = model::User::find().all(tx).await?;
                        for user in users {
                            let home =
                                format!("{}/{}", settings.user_homedirectory_prefix, user.user_id);
                            posix_upsert_user_attribute(
                                tx,
                                user.user_id,
                                "homedirectory",
                                home.into_bytes(),
                            )
                            .await?;
                        }
                    } else {
                        posix_clear_user_attribute(tx, "homedirectory").await?;
                    }
                    Ok(())
                })
            })
            .await?;
        logging::record(
            LogKind::PosixChange,
            Some("user homedirectory"),
            Some("reassign"),
        );
        Ok(())
    }

    #[instrument(skip(self), level = "info", err)]
    async fn reassign_user_loginshells(&self) -> Result<()> {
        require_kdc_ready()?;
        let settings = self.get_posix_settings().await?;
        self.sql_pool
            .transaction::<_, (), DomainError>(|tx| {
                Box::pin(async move {
                    if settings.user_loginshell_assign {
                        let users = model::User::find().all(tx).await?;
                        for user in users {
                            posix_upsert_user_attribute(
                                tx,
                                user.user_id,
                                "loginshell",
                                settings.user_loginshell_default.clone().into_bytes(),
                            )
                            .await?;
                        }
                    } else {
                        posix_clear_user_attribute(tx, "loginshell").await?;
                    }
                    Ok(())
                })
            })
            .await?;
        logging::record(
            LogKind::PosixChange,
            Some("user loginshell"),
            Some("reassign"),
        );
        Ok(())
    }
}

impl SqlBackendHandler {
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
            if !Self::is_uidnumber_taken(transaction, candidate, None).await? {
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
            if !Self::is_gidnumber_taken(transaction, candidate, None).await? {
                return Ok(candidate);
            }
            candidate += 1;
        }
        Err(DomainError::InternalError(format!(
            "No available gidNumber in range {}-{} (all taken)",
            start, max
        )))
    }

    pub(crate) async fn is_uidnumber_taken(
        transaction: &DatabaseTransaction,
        uid: i64,
        except_user: Option<&UserId>,
    ) -> Result<bool> {
        let mut taken = model::UserAttributes::find()
            .filter(model::UserAttributesColumn::AttributeName.eq("uidnumber"))
            .filter(model::UserAttributesColumn::Value.eq(uid.to_string().into_bytes()));
        if let Some(user_id) = except_user {
            taken = taken.filter(model::UserAttributesColumn::UserId.ne(user_id.clone()));
        }
        Ok(taken.count(transaction).await? > 0)
    }

    pub(crate) async fn is_gidnumber_taken(
        transaction: &DatabaseTransaction,
        gid: i64,
        except_group: Option<GroupId>,
    ) -> Result<bool> {
        let mut taken = model::GroupAttributes::find()
            .filter(model::GroupAttributesColumn::AttributeName.eq("gidnumber"))
            .filter(model::GroupAttributesColumn::Value.eq(gid.to_string().into_bytes()));
        if let Some(group_id) = except_group {
            taken = taken.filter(model::GroupAttributesColumn::GroupId.ne(group_id));
        }
        Ok(taken.count(transaction).await? > 0)
    }

    /// Rejects group gidNumbers outside 3000..=60000 or held by another group.
    pub(crate) async fn validate_group_posix_numbers(
        transaction: &DatabaseTransaction,
        numbers: &[(String, i64)],
        except_group: Option<GroupId>,
    ) -> Result<()> {
        for (name, value) in numbers.iter().filter(|(name, _)| name == "gidnumber") {
            if !(3000..=60000).contains(value) {
                return Err(DomainError::InternalError(format!(
                    "{name} must be between 3000 and 60000"
                )));
            }
            if Self::is_gidnumber_taken(transaction, *value, except_group).await? {
                return Err(DomainError::InternalError(format!(
                    "Number {value} is already assigned to another user/group"
                )));
            }
        }
        Ok(())
    }

    /// Rejects POSIX ids outside 3000..=60000 and uidNumbers held by another user;
    /// gidNumbers on users may repeat.
    pub(crate) async fn validate_posix_numbers(
        transaction: &DatabaseTransaction,
        numbers: &[(String, i64)],
        except_user: Option<&UserId>,
    ) -> Result<()> {
        for (name, value) in numbers {
            if name != "uidnumber" && name != "gidnumber" {
                continue;
            }
            if !(3000..=60000).contains(value) {
                return Err(DomainError::InternalError(format!(
                    "{name} must be between 3000 and 60000"
                )));
            }
            if name == "uidnumber"
                && Self::is_uidnumber_taken(transaction, *value, except_user).await?
            {
                return Err(DomainError::InternalError(format!(
                    "Number {value} is already assigned to another user/group"
                )));
            }
        }
        Ok(())
    }

    /// Fills in whichever POSIX attributes the settings auto-assign and the request left out.
    pub(crate) async fn assign_posix_defaults(
        transaction: &DatabaseTransaction,
        settings: &PosixSettings,
        user_id: &UserId,
        attributes: &mut Vec<Attribute>,
    ) -> Result<()> {
        let has = |name: &str| attributes.iter().any(|a| a.name.as_str() == name);
        let mut defaults = Vec::new();
        if settings.user_uidnumber_assign && !has("uidnumber") {
            let next_uid = Self::next_available_uid_number(
                transaction,
                settings.user_uidnumber_start,
                settings.user_uidnumber_max,
            )
            .await?;
            defaults.push(Attribute {
                name: "uidnumber".into(),
                value: AttributeValue::Integer(Cardinality::Singleton(next_uid)),
            });
        }
        if settings.user_gidnumber_assign && !has("gidnumber") {
            defaults.push(Attribute {
                name: "gidnumber".into(),
                value: AttributeValue::Integer(Cardinality::Singleton(
                    settings.user_gidnumber_start,
                )),
            });
        }
        if settings.user_loginshell_assign && !has("loginshell") {
            defaults.push(Attribute {
                name: "loginshell".into(),
                value: AttributeValue::String(Cardinality::Singleton(
                    settings.user_loginshell_default.clone(),
                )),
            });
        }
        if settings.user_homedirectory_assign && !has("homedirectory") {
            defaults.push(Attribute {
                name: "homedirectory".into(),
                value: AttributeValue::String(Cardinality::Singleton(format!(
                    "{}/{}",
                    settings.user_homedirectory_prefix, user_id
                ))),
            });
        }
        attributes.extend(defaults);
        Ok(())
    }
}

async fn posix_upsert_user_attribute(
    tx: &DatabaseTransaction,
    user_id: UserId,
    attribute: &str,
    value: Vec<u8>,
) -> Result<()> {
    let attr = model::user_attributes::ActiveModel {
        user_id: Set(user_id.clone()),
        attribute_name: Set(AttributeName::from(attribute)),
        value: Set(Serialized(value)),
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
    model::users::ActiveModel {
        user_id: Set(user_id),
        modified_date: Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    }
    .update(tx)
    .await?;
    Ok(())
}

async fn posix_clear_user_attribute(tx: &DatabaseTransaction, attribute: &str) -> Result<()> {
    model::UserAttributes::delete_many()
        .filter(model::user_attributes::Column::AttributeName.eq(attribute))
        .exec(tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::TestFixture;
    use lldap_domain::requests::{
        CreateGroupRequest, CreateUserRequest, UpdateGroupRequest, UpdateUserRequest,
    };
    use lldap_domain::types::GroupId;
    use lldap_domain_handlers::handler::{GroupBackendHandler, UserBackendHandler};
    use pretty_assertions::assert_eq;

    fn integer(name: &str, value: i64) -> Attribute {
        Attribute {
            name: name.into(),
            value: AttributeValue::Integer(Cardinality::Singleton(value)),
        }
    }

    fn set_attribute(user_id: &str, attribute: Attribute) -> UpdateUserRequest {
        UpdateUserRequest {
            user_id: UserId::new(user_id),
            email: None,
            display_name: None,
            delete_attributes: Vec::new(),
            insert_attributes: vec![attribute],
        }
    }

    async fn attribute_value(fixture: &TestFixture, user_id: &str, name: &str) -> AttributeValue {
        fixture
            .handler
            .get_user_details(&UserId::new(user_id))
            .await
            .unwrap()
            .attributes
            .into_iter()
            .find(|a| a.name.as_str() == name)
            .unwrap_or_else(|| panic!("{user_id} has no {name}"))
            .value
    }

    #[tokio::test]
    async fn test_user_uidnumber_is_unique_ranged_and_resubmittable() {
        let fixture = TestFixture::new().await;
        for _ in 0..2 {
            fixture
                .handler
                .update_user(set_attribute("bob", integer("uidnumber", 3005)))
                .await
                .unwrap();
        }
        assert_eq!(
            attribute_value(&fixture, "bob", "uidnumber").await,
            AttributeValue::Integer(Cardinality::Singleton(3005))
        );
        let err = fixture
            .handler
            .update_user(set_attribute("patrick", integer("uidnumber", 3005)))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already assigned"), "{err}");
        let err = fixture
            .handler
            .update_user(set_attribute("patrick", integer("uidnumber", 70000)))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("between 3000 and 60000"), "{err}");
    }

    fn set_group_attribute(group_id: GroupId, attribute: Attribute) -> UpdateGroupRequest {
        UpdateGroupRequest {
            group_id,
            display_name: None,
            delete_attributes: Vec::new(),
            insert_attributes: vec![attribute],
        }
    }

    async fn group_gid(fixture: &TestFixture, group_id: GroupId) -> Option<AttributeValue> {
        fixture
            .handler
            .get_group_details(group_id)
            .await
            .unwrap()
            .attributes
            .into_iter()
            .find(|a| a.name.as_str() == "gidnumber")
            .map(|a| a.value)
    }

    #[tokio::test]
    async fn test_group_gidnumber_is_unique_and_ranged_but_may_be_resubmitted() {
        let fixture = TestFixture::new().await;
        for _ in 0..2 {
            fixture
                .handler
                .update_group(set_group_attribute(
                    fixture.groups[0],
                    integer("gidnumber", 45000),
                ))
                .await
                .unwrap();
        }
        assert_eq!(
            group_gid(&fixture, fixture.groups[0]).await,
            Some(AttributeValue::Integer(Cardinality::Singleton(45000)))
        );
        let err = fixture
            .handler
            .update_group(set_group_attribute(
                fixture.groups[1],
                integer("gidnumber", 45000),
            ))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already assigned"), "{err}");
        let err = fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "posix".into(),
                attributes: vec![integer("gidnumber", 45000)],
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already assigned"), "{err}");
        let err = fixture
            .handler
            .create_group(CreateGroupRequest {
                display_name: "posix".into(),
                attributes: vec![integer("gidnumber", 70000)],
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("between 3000 and 60000"), "{err}");
    }

    #[tokio::test]
    async fn test_create_assigns_the_configured_posix_defaults() {
        let fixture = TestFixture::new().await;
        fixture
            .handler
            .set_posix_settings(PosixSettings {
                user_uidnumber_assign: true,
                user_uidnumber_start: 3000,
                user_uidnumber_max: 3010,
                user_gidnumber_assign: true,
                user_gidnumber_start: 4000,
                user_loginshell_assign: true,
                user_loginshell_default: "/bin/zsh".to_owned(),
                user_homedirectory_assign: true,
                user_homedirectory_prefix: "/home".to_owned(),
                ..PosixSettings::default()
            })
            .await
            .unwrap();
        fixture
            .handler
            .update_user(set_attribute("bob", integer("uidnumber", 3000)))
            .await
            .unwrap();
        fixture
            .handler
            .create_user(CreateUserRequest {
                user_id: UserId::new("posix"),
                email: "posix@example.com".into(),
                display_name: None,
                attributes: vec![integer("gidnumber", 4242)],
            })
            .await
            .unwrap();
        assert_eq!(
            attribute_value(&fixture, "posix", "uidnumber").await,
            AttributeValue::Integer(Cardinality::Singleton(3001))
        );
        assert_eq!(
            attribute_value(&fixture, "posix", "gidnumber").await,
            AttributeValue::Integer(Cardinality::Singleton(4242))
        );
        assert_eq!(
            attribute_value(&fixture, "posix", "loginshell").await,
            AttributeValue::String(Cardinality::Singleton("/bin/zsh".to_owned()))
        );
        assert_eq!(
            attribute_value(&fixture, "posix", "homedirectory").await,
            AttributeValue::String(Cardinality::Singleton("/home/posix".to_owned()))
        );
    }
}
