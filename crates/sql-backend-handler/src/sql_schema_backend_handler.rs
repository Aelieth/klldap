use crate::sql_backend_handler::SqlBackendHandler;
use async_trait::async_trait;
use lldap_domain::{
    requests::CreateAttributeRequest,
    types::{AttributeName, LdapObjectClass},
};
use lldap_domain_handlers::handler::{ReadSchemaBackendHandler, SchemaBackendHandler};
use lldap_domain_handlers::kerberos::require_kdc_ready;
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_domain_model::{
    error::{DomainError, Result},
    model,
};
use lldap_schema::{AttributeSchema, PublicSchema};
use sea_orm::{
    ActiveModelTrait, DatabaseTransaction, EntityTrait, QueryOrder, Set, TransactionTrait,
};

#[async_trait]
impl ReadSchemaBackendHandler for SqlBackendHandler {
    async fn get_schema(&self) -> Result<PublicSchema> {
        Ok(self
            .sql_pool
            .transaction::<_, PublicSchema, DomainError>(|transaction| {
                Box::pin(async move { Self::get_schema_with_transaction(transaction).await })
            })
            .await?)
    }
}

#[async_trait]
impl SchemaBackendHandler for SqlBackendHandler {
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        require_kdc_ready()?;
        let name = request.name.clone();
        let new_attribute = model::user_attribute_schema::ActiveModel {
            attribute_name: Set(request.name),
            attribute_type: Set(request.attribute_type),
            is_list: Set(request.is_list),
            is_user_visible: Set(request.is_visible),
            is_user_editable: Set(request.is_editable),
            is_hardcoded: Set(false),
            is_readonly: Set(false), // custom attributes are never readonly
            aliases: Set("[]".to_string()),
        };
        new_attribute.insert(&self.sql_pool).await?;
        logging::record(
            LogKind::SchemaChange,
            Some(name.as_str()),
            Some("add user attribute"),
        );
        Ok(())
    }

    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        require_kdc_ready()?;
        let name = request.name.clone();
        let new_attribute = model::group_attribute_schema::ActiveModel {
            attribute_name: Set(request.name),
            attribute_type: Set(request.attribute_type),
            is_list: Set(request.is_list),
            is_group_visible: Set(request.is_visible),
            is_group_editable: Set(request.is_editable),
            is_hardcoded: Set(false),
            is_readonly: Set(false), // custom attributes are never readonly
            aliases: Set("[]".to_string()),
        };
        new_attribute.insert(&self.sql_pool).await?;
        logging::record(
            LogKind::SchemaChange,
            Some(name.as_str()),
            Some("add group attribute"),
        );
        Ok(())
    }

    async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()> {
        require_kdc_ready()?;
        model::UserAttributeSchema::delete_by_id(name.clone())
            .exec(&self.sql_pool)
            .await?;
        logging::record(
            LogKind::SchemaChange,
            Some(name.as_str()),
            Some("delete user attribute"),
        );
        Ok(())
    }

    async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()> {
        require_kdc_ready()?;
        model::GroupAttributeSchema::delete_by_id(name.clone())
            .exec(&self.sql_pool)
            .await?;
        logging::record(
            LogKind::SchemaChange,
            Some(name.as_str()),
            Some("delete group attribute"),
        );
        Ok(())
    }

    async fn add_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        require_kdc_ready()?;
        let mut name_key = name.to_string();
        name_key.make_ascii_lowercase();
        model::user_object_classes::ActiveModel {
            lower_object_class: Set(name_key),
            object_class: Set(name.clone()),
        }
        .insert(&self.sql_pool)
        .await?;
        logging::record(
            LogKind::SchemaChange,
            Some(name.as_str()),
            Some("add user object class"),
        );
        Ok(())
    }

    async fn add_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        require_kdc_ready()?;
        let mut name_key = name.to_string();
        name_key.make_ascii_lowercase();
        model::group_object_classes::ActiveModel {
            lower_object_class: Set(name_key),
            object_class: Set(name.clone()),
        }
        .insert(&self.sql_pool)
        .await?;
        logging::record(
            LogKind::SchemaChange,
            Some(name.as_str()),
            Some("add group object class"),
        );
        Ok(())
    }

    async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        require_kdc_ready()?;
        model::UserObjectClasses::delete_by_id(name.as_str().to_ascii_lowercase())
            .exec(&self.sql_pool)
            .await?;
        logging::record(
            LogKind::SchemaChange,
            Some(name.as_str()),
            Some("delete user object class"),
        );
        Ok(())
    }

    async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        require_kdc_ready()?;
        model::GroupObjectClasses::delete_by_id(name.as_str().to_ascii_lowercase())
            .exec(&self.sql_pool)
            .await?;
        logging::record(
            LogKind::SchemaChange,
            Some(name.as_str()),
            Some("delete group object class"),
        );
        Ok(())
    }
}

impl SqlBackendHandler {
    pub(crate) async fn get_schema_with_transaction(
        transaction: &DatabaseTransaction,
    ) -> Result<PublicSchema> {
        let mut full = PublicSchema::get().0; // inner Schema

        let dynamic_user_attrs: Vec<_> = Self::get_user_attributes(transaction)
            .await?
            .into_iter()
            .filter(|a| !a.is_hardcoded) // only keep custom ones
            .collect();

        let dynamic_group_attrs: Vec<_> = Self::get_group_attributes(transaction)
            .await?
            .into_iter()
            .filter(|a| !a.is_hardcoded)
            .collect();

        for attr in dynamic_user_attrs {
            if !full
                .user_attributes
                .attributes
                .iter()
                .any(|existing| existing.name == attr.name)
            {
                full.user_attributes.attributes.push(attr);
            }
        }

        for attr in dynamic_group_attrs {
            if !full
                .group_attributes
                .attributes
                .iter()
                .any(|existing| existing.name == attr.name)
            {
                full.group_attributes.attributes.push(attr);
            }
        }

        full.posix_settings = {
            let s = Self::get_posix_settings_with_transaction(transaction).await?;
            lldap_schema::schema::PosixSettings {
                user_uidnumber_assign: s.user_uidnumber_assign,
                user_uidnumber_start: s.user_uidnumber_start,
                user_uidnumber_max: s.user_uidnumber_max,
                user_gidnumber_assign: s.user_gidnumber_assign,
                user_gidnumber_start: s.user_gidnumber_start,
                user_loginshell_assign: s.user_loginshell_assign,
                user_loginshell_default: s.user_loginshell_default,
                user_homedirectory_assign: s.user_homedirectory_assign,
                user_homedirectory_prefix: s.user_homedirectory_prefix,
                group_gidnumber_assign: s.group_gidnumber_assign,
                group_gidnumber_start: s.group_gidnumber_start,
                group_gidnumber_max: s.group_gidnumber_max,
            }
        };

        full.extra_user_object_classes = Self::get_user_object_classes(transaction)
            .await?
            .into_iter()
            .map(|oc| oc.into_string())
            .collect();

        full.extra_group_object_classes = Self::get_group_object_classes(transaction)
            .await?
            .into_iter()
            .map(|oc| oc.into_string())
            .collect();

        Ok(PublicSchema(full))
    }

    async fn get_user_attributes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<AttributeSchema>> {
        Ok(model::UserAttributeSchema::find()
            .order_by_asc(model::UserAttributeSchemaColumn::AttributeName)
            .all(transaction)
            .await?
            .into_iter()
            .map(|m| AttributeSchema {
                name: m.attribute_name.into_string(),
                aliases: serde_json::from_str(&m.aliases).unwrap_or_default(),
                attribute_type: m.attribute_type,
                is_list: m.is_list,
                is_visible: m.is_user_visible,
                is_editable: m.is_user_editable,
                is_hardcoded: m.is_hardcoded,
                is_readonly: m.is_readonly,
            })
            .collect())
    }

    async fn get_group_attributes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<AttributeSchema>> {
        Ok(model::GroupAttributeSchema::find()
            .order_by_asc(model::GroupAttributeSchemaColumn::AttributeName)
            .all(transaction)
            .await?
            .into_iter()
            .map(|m| AttributeSchema {
                name: m.attribute_name.into_string(),
                aliases: serde_json::from_str(&m.aliases).unwrap_or_default(),
                attribute_type: m.attribute_type,
                is_list: m.is_list,
                is_visible: m.is_group_visible,
                is_editable: m.is_group_editable,
                is_hardcoded: m.is_hardcoded,
                is_readonly: m.is_readonly,
            })
            .collect())
    }

    async fn get_user_object_classes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<LdapObjectClass>> {
        Ok(model::UserObjectClasses::find()
            .order_by_asc(model::UserObjectClassesColumn::ObjectClass)
            .all(transaction)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn get_group_object_classes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<LdapObjectClass>> {
        Ok(model::GroupObjectClasses::find()
            .order_by_asc(model::GroupObjectClassesColumn::ObjectClass)
            .all(transaction)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::*;
    use lldap_domain::requests::UpdateUserRequest;
    use lldap_domain::types::{Attribute, AttributeType, LdapObjectClass};
    use lldap_domain_handlers::handler::{UserBackendHandler, UserRequestFilter};
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_default_schema() {
        let fixture = TestFixture::new().await;
        let schema = fixture.handler.get_schema().await.unwrap();

        assert!(
            schema
                .user_attributes()
                .get_by_name_or_alias("avatar")
                .is_some()
        );
        assert!(
            schema
                .user_attributes()
                .get_by_name_or_alias("kerberossync")
                .is_some()
        );
        assert!(
            schema
                .user_attributes()
                .get_by_name_or_alias("uidnumber")
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_user_attribute_add_and_delete() {
        let fixture = TestFixture::new().await;

        let new_attribute = CreateAttributeRequest {
            name: "new_attribute".into(),
            attribute_type: AttributeType::Integer,
            is_list: true,
            is_visible: false,
            is_editable: false,
        };

        fixture
            .handler
            .add_user_attribute(new_attribute)
            .await
            .unwrap();

        let schema = fixture.handler.get_schema().await.unwrap();
        assert!(
            schema
                .user_attributes()
                .get_by_name_or_alias("new_attribute")
                .is_some()
        );

        fixture
            .handler
            .delete_user_attribute(&"new_attribute".into())
            .await
            .unwrap();

        let schema = fixture.handler.get_schema().await.unwrap();
        assert!(
            schema
                .user_attributes()
                .get_by_name_or_alias("new_attribute")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_user_attribute_present_filter() {
        let fixture = TestFixture::new().await;

        let new_attribute = CreateAttributeRequest {
            name: "new_attribute".into(),
            attribute_type: AttributeType::Integer,
            is_list: true,
            is_visible: false,
            is_editable: false,
        };

        fixture
            .handler
            .add_user_attribute(new_attribute)
            .await
            .unwrap();

        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: "bob".into(),
                insert_attributes: vec![Attribute {
                    name: "new_attribute".into(),
                    value: vec![3].into(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();

        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::CustomAttributePresent(
                "new_attribute".into(),
            )),
        )
        .await;

        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_group_attribute_add_and_delete() {
        let fixture = TestFixture::new().await;

        let new_attribute = CreateAttributeRequest {
            name: "NeW_aTTribute".into(),
            attribute_type: AttributeType::Avatar,
            is_list: false,
            is_visible: true,
            is_editable: false,
        };

        fixture
            .handler
            .add_group_attribute(new_attribute)
            .await
            .unwrap();

        let expected_value = AttributeSchema {
            name: "new_attribute".into(),
            aliases: vec![],
            attribute_type: AttributeType::Avatar,
            is_list: false,
            is_visible: true,
            is_editable: false,
            is_hardcoded: false,
            is_readonly: false,
        };

        let schema = fixture.handler.get_schema().await.unwrap();
        assert!(
            schema
                .group_attributes()
                .attributes
                .contains(&expected_value)
        );

        fixture
            .handler
            .delete_group_attribute(&"new_attriBUte".into())
            .await
            .unwrap();

        let schema = fixture.handler.get_schema().await.unwrap();
        assert!(
            !schema
                .group_attributes()
                .attributes
                .contains(&expected_value)
        );
    }

    #[tokio::test]
    async fn test_user_object_class_add_and_delete() {
        let fixture = TestFixture::new().await;
        let new_object_class = LdapObjectClass::new("newObjectClass");

        fixture
            .handler
            .add_user_object_class(&new_object_class)
            .await
            .unwrap();

        let schema = fixture.handler.get_schema().await.unwrap();
        assert_eq!(
            schema.0.extra_user_object_classes,
            vec!["newObjectClass".to_string()]
        );

        fixture
            .handler
            .add_user_object_class(&LdapObjectClass::new("newobjEctclass"))
            .await
            .expect_err("Should not be able to add the same object class twice");

        let schema = fixture.handler.get_schema().await.unwrap();
        assert_eq!(
            schema.0.extra_user_object_classes,
            vec!["newObjectClass".to_string()]
        );

        fixture
            .handler
            .delete_user_object_class(&new_object_class)
            .await
            .unwrap();

        let schema = fixture.handler.get_schema().await.unwrap();
        assert!(schema.0.extra_user_object_classes.is_empty());
    }

    #[tokio::test]
    async fn test_schema_does_not_leak_aliases_as_top_level_names() {
        let fixture = crate::sql_backend_handler::tests::TestFixture::new().await;
        let schema = fixture.handler.get_schema().await.unwrap();

        let user_attrs = schema.user_attributes();

        let top_level_names: Vec<&str> = user_attrs
            .attributes
            .iter()
            .map(|a| a.name.as_str())
            .collect();

        // Aliases must never appear as top-level names.
        let forbidden_alias_names = ["first_name", "last_name", "givenName", "sn"];

        for forbidden in forbidden_alias_names {
            assert!(
                !top_level_names.contains(&forbidden),
                "Alias '{}' should not appear as a top-level attribute name in the schema. \
             It must only exist inside the `aliases` field of its canonical attribute.",
                forbidden
            );
        }

        assert!(
            top_level_names.contains(&"firstname"),
            "Canonical name 'firstname' must be present"
        );
        assert!(
            top_level_names.contains(&"lastname"),
            "Canonical name 'lastname' must be present"
        );

        for attr in &user_attrs.attributes {
            for alias in &attr.aliases {
                assert!(
                    !top_level_names.contains(&alias.as_str()),
                    "Alias '{}' from attribute '{}' is also appearing as a top-level name. \
                 This indicates alias leakage in the schema.",
                    alias,
                    attr.name
                );
            }
        }
    }
}
