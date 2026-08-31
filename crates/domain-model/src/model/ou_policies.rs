use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "ou_policies")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub ou_key: String,
    pub policy_id: Option<i32>,
    pub block_inheritance: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
