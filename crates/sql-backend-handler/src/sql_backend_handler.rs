use crate::sql_policy_read::StatementBound;
use crate::sql_tables::DbConnection;
use itertools::Itertools;
use lldap_auth::opaque::server::ServerSetup;
use lldap_domain::types::{Attribute, AttributeName, AttributeValue, UserId};
use lldap_domain_handlers::enforcement::{self, PolicyCache};
use lldap_domain_handlers::kdc_proof::ProofSettings;
use lldap_domain_handlers::lockout::{Lockout, lockout};
use lldap_domain_handlers::mfa::MfaPolicy;
use lldap_schema::PublicSchema;
use sea_orm::sea_query::{Cond, IntoCondition, SimpleExpr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use tracing::warn;

pub(crate) fn bool_to_expr(b: bool) -> Cond {
    SimpleExpr::Value(b.into()).into_condition()
}

pub(crate) fn get_repeated_filter<F>(
    fs: Vec<F>,
    condition: Cond,
    default_value: bool,
    to_expr: fn(F) -> Cond,
) -> Cond {
    if fs.is_empty() {
        bool_to_expr(default_value)
    } else {
        fs.into_iter().map(to_expr).fold(condition, Cond::add)
    }
}

pub(crate) fn is_backend_writable_readonly_attribute(name: &str) -> bool {
    matches!(
        name,
        "ou" | lldap_schema::KERBEROS_SYNC | "allowedous" | "krb_principal_name"
    )
}

/// Names only, never values: what an update touched, for the log detail.
pub(crate) fn describe_changes(
    inserted: &[Attribute],
    deleted: &[AttributeName],
    fields: &[(&str, bool)],
) -> String {
    inserted
        .iter()
        .map(|a| a.name.as_str().to_owned())
        .chain(deleted.iter().map(|a| format!("-{}", a.as_str())))
        .chain(
            fields
                .iter()
                .filter(|(_, changed)| *changed)
                .map(|(name, _)| (*name).to_owned()),
        )
        .join(", ")
}

pub(crate) fn attribute_value_to_db_bytes(value: &AttributeValue) -> Vec<u8> {
    lldap_domain_model::model::codec::encode_attribute_value(value)
}

#[derive(Clone)]
pub struct SqlBackendHandler {
    pub(crate) opaque_setup: ServerSetup,
    pub(crate) sql_pool: DbConnection,
    pub(crate) read_pool: DbConnection,
    /// The explicit server-wide `enable_mfa`; `None` lets the OUs decide.
    pub(crate) mfa_policy: Option<MfaPolicy>,
    /// What a proven second factor opens at the KDC; `None` without a realm.
    pub(crate) proofs: Option<ProofSettings>,
    /// A `totp_steps` row was written since the last prune; true at start, for one prune then.
    pub(crate) codes_written: Arc<AtomicBool>,
    pub(crate) policy_cache: &'static PolicyCache,
    pub(crate) lockout: &'static Lockout,
    policy_changes: Arc<AtomicU64>,
    pub(crate) statement_bound: Arc<OnceLock<StatementBound>>,
}

impl SqlBackendHandler {
    pub fn new(opaque_setup: ServerSetup, sql_pool: DbConnection) -> Self {
        SqlBackendHandler {
            opaque_setup,
            read_pool: sql_pool.clone(),
            sql_pool,
            mfa_policy: None,
            proofs: None,
            codes_written: Arc::new(AtomicBool::new(true)),
            policy_cache: enforcement::policy_cache(),
            lockout: lockout(),
            policy_changes: Arc::default(),
            statement_bound: Arc::default(),
        }
    }

    /// The process's view and queue unless a test gives its own.
    pub fn with_lockout(mut self, lockout: &'static Lockout) -> Self {
        self.lockout = lockout;
        self
    }

    /// The process's cache unless a test gives its own.
    pub fn with_policy_cache(mut self, policy_cache: &'static PolicyCache) -> Self {
        policy_cache.set_mfa_policy(self.mfa_policy);
        policy_cache.set_proofs(self.proofs);
        self.policy_cache = policy_cache;
        self
    }

    pub fn with_proofs(mut self, proofs: Option<ProofSettings>) -> Self {
        self.policy_cache.set_proofs(proofs);
        self.proofs = proofs;
        self
    }

    /// The log lookups read on this pool, so a slow summary cannot queue binds behind it.
    pub fn with_read_pool(mut self, read_pool: DbConnection) -> Self {
        self.read_pool = read_pool;
        self
    }

    pub fn with_mfa_policy(self, mfa_policy: MfaPolicy) -> Self {
        self.with_mfa_setting(Some(mfa_policy))
    }

    pub fn with_mfa_setting(mut self, mfa_policy: Option<MfaPolicy>) -> Self {
        self.policy_cache.set_mfa_policy(mfa_policy);
        self.mfa_policy = mfa_policy;
        self
    }

    pub fn pool(&self) -> &DbConnection {
        &self.sql_pool
    }

    pub(crate) async fn policy_changed(&self) {
        self.policy_changes.fetch_add(1, Ordering::Relaxed);
        let filled = match self.lockout.follow_policies(self, self.policy_cache).await {
            Ok(filled) => filled,
            Err(e) => {
                warn!("The lockout did not follow a policy change: {e}");
                false
            }
        };
        if !filled {
            enforcement::policy_changed(self, self.policy_cache).await;
        }
    }

    pub(crate) async fn user_written(&self, user: &UserId) {
        self.policy_changes.fetch_add(1, Ordering::Relaxed);
        enforcement::user_written(self, self.policy_cache, user).await;
    }

    #[cfg(test)]
    pub(crate) fn policy_changes(&self) -> u64 {
        self.policy_changes.load(Ordering::Relaxed)
    }

    /// Hardcoded aliases live in the static PublicSchema, not in the DB copy.
    pub(crate) fn canonical_user_attribute_name(
        _schema: &PublicSchema,
        name: &str,
    ) -> AttributeName {
        PublicSchema::shared()
            .user_attributes()
            .get_by_name_or_alias(name)
            .map(|s| s.name.clone().into())
            .unwrap_or_else(|| AttributeName::from(name))
    }

    pub(crate) fn canonical_group_attribute_name(
        _schema: &PublicSchema,
        name: &str,
    ) -> AttributeName {
        PublicSchema::shared()
            .group_attributes()
            .get_by_name_or_alias(name)
            .map(|s| s.name.clone().into())
            .unwrap_or_else(|| AttributeName::from(name))
    }
}

use lldap_domain_handlers::handler::BackendHandler;

impl BackendHandler for SqlBackendHandler {}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::sql_tables::init_table;
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::{
        requests::{CreateGroupRequest, CreateUserRequest},
        types::{Attribute as DomainAttribute, GroupId, UserId},
    };
    use lldap_domain_handlers::handler::{
        GroupBackendHandler, UserBackendHandler, UserListerBackendHandler, UserRequestFilter,
    };
    use pretty_assertions::assert_eq;
    use sea_orm::Database;

    pub async fn get_in_memory_db() -> DbConnection {
        crate::logging::init_for_tests();
        let mut sql_opt = sea_orm::ConnectOptions::new("sqlite::memory:".to_owned());
        sql_opt
            .max_connections(1)
            .sqlx_logging(true)
            .sqlx_logging_level(log::LevelFilter::Debug);
        Database::connect(sql_opt).await.unwrap()
    }

    pub async fn get_initialized_db() -> DbConnection {
        let sql_pool = get_in_memory_db().await;
        init_table(&sql_pool).await.unwrap();
        sql_pool
    }

    pub async fn insert_user(handler: &SqlBackendHandler, name: &str, pass: &str) {
        insert_user_no_password(handler, name).await;
        lldap_opaque_handler::register_password(handler, name.into(), pass.as_bytes())
            .await
            .unwrap();
    }

    pub async fn insert_user_no_password(handler: &SqlBackendHandler, name: &str) {
        handler
            .create_user(CreateUserRequest {
                user_id: UserId::new(name),
                email: format!("{name}@bob.bob").into(),
                display_name: Some("display ".to_string() + name),
                attributes: vec![
                    DomainAttribute {
                        name: "firstname".into(), // canonical
                        value: ("first ".to_string() + name).into(),
                    },
                    DomainAttribute {
                        name: "lastname".into(), // canonical
                        value: ("last ".to_string() + name).into(),
                    },
                ],
            })
            .await
            .unwrap();
    }

    pub async fn insert_group(handler: &SqlBackendHandler, name: &str) -> GroupId {
        handler
            .create_group(CreateGroupRequest {
                display_name: name.into(),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    pub async fn insert_membership(handler: &SqlBackendHandler, group_id: GroupId, user_id: &str) {
        handler
            .add_user_to_group(&UserId::new(user_id), group_id)
            .await
            .unwrap();
    }

    pub async fn get_user_names(
        handler: &SqlBackendHandler,
        filters: Option<UserRequestFilter>,
    ) -> Vec<String> {
        handler
            .list_users(filters, false)
            .await
            .unwrap()
            .into_iter()
            .map(|u| u.user.user_id.to_string())
            .collect::<Vec<_>>()
    }

    pub struct TestFixture {
        pub handler: SqlBackendHandler,
        pub groups: Vec<GroupId>,
    }

    impl TestFixture {
        pub async fn new() -> Self {
            let sql_pool = get_initialized_db().await;
            let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
            insert_user_no_password(&handler, "bob").await;
            insert_user_no_password(&handler, "patrick").await;
            insert_user_no_password(&handler, "John").await;
            insert_user_no_password(&handler, "NoGroup").await;
            let mut groups = vec![];
            groups.push(insert_group(&handler, "Best Group").await);
            groups.push(insert_group(&handler, "Worst Group").await);
            groups.push(insert_group(&handler, "Empty Group").await);
            insert_membership(&handler, groups[0], "bob").await;
            insert_membership(&handler, groups[0], "patrick").await;
            insert_membership(&handler, groups[1], "patrick").await;
            insert_membership(&handler, groups[1], "John").await;
            Self { handler, groups }
        }
    }

    #[tokio::test]
    async fn test_sql_injection() {
        let sql_pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), sql_pool);
        let user_name = UserId::new(r#"bob"e"i'o;aü"#);
        insert_user_no_password(&handler, user_name.as_str()).await;
        {
            let users = handler
                .list_users(None, false)
                .await
                .unwrap()
                .into_iter()
                .map(|u| u.user.user_id)
                .collect::<Vec<_>>();

            assert_eq!(users, vec![user_name.clone()]);
            let user = handler.get_user_details(&user_name).await.unwrap();
            assert_eq!(user.user_id, user_name);
        }
    }
}
