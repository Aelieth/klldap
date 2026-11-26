use async_trait::async_trait;
use chrono::NaiveDateTime;
use lldap_domain::types::UserId;
use lldap_domain_model::error::Result;
use std::collections::HashSet;

#[async_trait]
pub trait TcpBackendHandler: Sync {
    async fn get_jwt_blacklist(&self) -> anyhow::Result<HashSet<u64>>;
    async fn create_refresh_token(&self, user: &UserId) -> Result<(String, chrono::Duration)>;
    async fn register_jwt(
        &self,
        user: &UserId,
        jwt_hash: u64,
        expiry_date: NaiveDateTime,
    ) -> Result<()>;
    async fn check_token(&self, refresh_token_hash: u64, user: &UserId) -> Result<bool>;
    async fn blacklist_jwts(&self, user: &UserId) -> Result<HashSet<u64>>;
    /// Ends one access token, in the store a logout ends each of its user's in.
    async fn blacklist_jwt(&self, jwt_hash: u64) -> Result<()>;
    async fn delete_refresh_token(&self, refresh_token_hash: u64) -> Result<()>;
    /// Ends every refresh token of `user`, so none of its sessions makes a new access token.
    async fn delete_refresh_tokens(&self, user: &UserId) -> Result<()>;

    /// Request a token to reset a user's password.
    /// If the user doesn't exist, returns `Ok(None)`, otherwise `Ok(Some(token))`.
    async fn start_password_reset(&self, user: &UserId) -> Result<Option<String>>;

    /// Get the user ID associated with a password reset token.
    async fn get_user_id_for_password_reset_token(&self, token: &str) -> Result<UserId>;

    async fn delete_password_reset_token(&self, token: &str) -> Result<()>;
}
