use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "logs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub timestamp: chrono::NaiveDateTime,
    pub kind: String,
    pub success: bool,
    pub protocol: String,
    pub actor: Option<String>,
    pub target: Option<String>,
    pub peer: Option<String>,
    pub forwarded_for: Option<String>,
    pub detail: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
