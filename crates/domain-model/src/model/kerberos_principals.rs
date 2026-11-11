use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "kerberos_principals")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_type = "String(StringLen::N(255))"
    )]
    pub name: String,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub user_id: Option<String>,
    #[sea_orm(column_type = "Blob")]
    pub record: Vec<u8>,
    pub has_keys: bool,
    pub disabled: bool,
    pub kvno: i32,
    pub expiration: Option<chrono::NaiveDateTime>,
    pub password_expiration: Option<chrono::NaiveDateTime>,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub policy: Option<String>,
    pub modified_date: chrono::NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
