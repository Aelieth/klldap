use sea_orm::entity::prelude::*;

use lldap_domain::types::UserId;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "login_lockouts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: UserId,
    pub fail_count: i32,
    pub last_failed: Option<chrono::NaiveDateTime>,
    pub last_success: Option<chrono::NaiveDateTime>,
    pub last_admin_unlock: Option<chrono::NaiveDateTime>,
    pub lock_logged: Option<chrono::NaiveDateTime>,
    pub split_start: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
