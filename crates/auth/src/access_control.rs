use crate::types::UserId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Permission {
    Admin,
    PasswordManager,
    Readonly,
    Regular,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationResults {
    pub user: UserId,
    pub permission: Permission,
}

impl ValidationResults {
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.permission == Permission::Admin
    }

    #[must_use]
    pub fn can_read_all(&self) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::Readonly
            || self.permission == Permission::PasswordManager
    }

    #[must_use]
    pub fn can_read(&self, user: &UserId) -> bool {
        self.permission == Permission::Admin
            || self.permission == Permission::PasswordManager
            || self.permission == Permission::Readonly
            || &self.user == user
    }

    #[must_use]
    pub fn can_change_password(&self, user: &UserId, user_is_admin: bool) -> bool {
        self.permission == Permission::Admin
            || (self.permission == Permission::PasswordManager && !user_is_admin)
            || &self.user == user
    }

    #[must_use]
    pub fn can_write(&self, user: &UserId) -> bool {
        self.permission == Permission::Admin || &self.user == user
    }

    // A password manager cannot drop its own factor. Under "always", GraphQL refuses
    // self-reset; admins can still clear others (an admin session could mint a new admin).
    #[must_use]
    pub fn can_reset_mfa(&self, user: &UserId, user_is_admin: bool) -> bool {
        self.permission == Permission::Admin
            || (self.permission == Permission::PasswordManager
                && !user_is_admin
                && &self.user != user)
    }
}
