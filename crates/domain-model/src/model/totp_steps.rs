use sea_orm::entity::prelude::*;

use lldap_domain::types::UserId;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "totp_steps")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: UserId,
    #[sea_orm(primary_key, auto_increment = false)]
    pub step: i64,
    pub failures: i16,
    pub used: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
