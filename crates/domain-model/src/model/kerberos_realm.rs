use sea_orm::entity::prelude::*;
use sea_orm::sea_query::extension::mysql::MySqlType;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "kerberos_realm")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    #[sea_orm(column_type = "String(StringLen::N(255))")]
    pub realm: String,
    pub generation: i64,
    pub open: bool,
    #[sea_orm(column_type = "Custom(SeaRc::new(MySqlType::LongBlob))")]
    pub state: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
