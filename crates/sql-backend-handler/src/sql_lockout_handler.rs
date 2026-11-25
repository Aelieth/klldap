use crate::sql_activity_handler::{
    move_recording, recording_in, reenable_user_on, success_statement,
};
use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_log_handler::to_active_model;
use crate::sql_opaque_handler::invalid_credentials;
use crate::sql_policy_handler::decode_items;
use crate::sql_tables::DbConnection;
use async_trait::async_trait;
use lldap_domain::types::{UserId, Uuid};
use lldap_domain_handlers::enforcement::{Door, UNREADABLE, inactive_since};
use lldap_domain_handlers::handler::{LockoutBackendHandler, SignInState};
use lldap_domain_handlers::inactivity::REENABLED_BY_ADMIN;
use lldap_domain_handlers::instant::{Timestamp, from_naive, to_naive};
use lldap_domain_handlers::lockout::{
    BATCH_LIMIT, LOCKED_OUT, LockRow, LockState, LockStore, LockWrite, SplitMark, Step, StoredLock,
    UNLOCKED_BY_ADMIN, Written, lock_clock, record_account_lock, sets_threshold,
};
use lldap_domain_handlers::logging::{self, LogEvent, LogKind};
use lldap_domain_handlers::warn_limited;
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{
        self, LoginLockoutsColumn, OuPoliciesColumn, PoliciesColumn, UserColumn, system_config,
    },
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, Condition, ConnectionTrait, DbBackend, EntityTrait, QueryFilter,
    QuerySelect, Statement, TransactionTrait, Value, sea_query::OnConflict,
};
use std::collections::HashMap;
use tracing::debug;

const COLUMNS: [&str; 4] = ["fail_count", "last_failed", "last_success", "lock_logged"];
/// The counting period, raised by the change that makes the first threshold effective.
pub(crate) const PERIOD_KEY: &str = "lockout_period";

pub(crate) fn numbered(backend: DbBackend, sql: &str) -> String {
    if backend != DbBackend::Postgres {
        return sql.to_owned();
    }
    let mut out = String::with_capacity(sql.len() + 16);
    let mut n = 0;
    for c in sql.chars() {
        if c == '?' {
            n += 1;
            out.push_str(&format!("${n}"));
        } else {
            out.push(c);
        }
    }
    out
}

fn name(user: &UserId) -> Value {
    Value::from(user.as_str().to_owned())
}

fn values(row: &LockRow) -> [Value; 5] {
    [
        Value::from(i32::try_from(row.fail_count).unwrap_or(i32::MAX)),
        row.last_failed.map(to_naive).into(),
        row.last_success.map(to_naive).into(),
        row.lock_logged.map(to_naive).into(),
        row.last_admin_unlock.map(to_naive).into(),
    ]
}

pub(crate) fn quoted(backend: DbBackend) -> (&'static str, &'static str, &'static str) {
    match backend {
        DbBackend::MySql => ("`key`", "`value`", " FROM DUAL"),
        DbBackend::Postgres | DbBackend::Sqlite => ("\"key\"", "\"value\"", ""),
    }
}

/// `SELECT <values>` for one account, in `period`: nothing when the name is no such account.
fn guarded(backend: DbBackend, values: &str, uuid: Option<&Uuid>) -> String {
    let (key, value, dual) = quoted(backend);
    let same = if uuid.is_some() {
        " AND users.uuid = ?"
    } else {
        ""
    };
    format!(
        "SELECT {values}{dual} WHERE EXISTS (SELECT 1 FROM users WHERE users.user_id = ?{same}) \
         AND COALESCE((SELECT {value} FROM system_config WHERE {key} = '{PERIOD_KEY}'), '0') = ?"
    )
}

fn guard_binds(user: &UserId, uuid: Option<&Uuid>, period: &str) -> Vec<Value> {
    let mut binds = vec![name(user)];
    binds.extend(uuid.map(|uuid| Value::from(uuid.as_str().to_owned())));
    binds.push(Value::from(period.to_owned()));
    binds
}

/// The row as it stands, for a user who exists, in `period`, unless the stored one carries a
/// later unlock.
pub(crate) fn put_statement(
    backend: DbBackend,
    period: &str,
    uuid: Option<&Uuid>,
    user: &UserId,
    row: &LockRow,
) -> Statement {
    let insert = format!(
        "INSERT INTO login_lockouts (user_id, fail_count, last_failed, last_success, \
         lock_logged, last_admin_unlock) {}",
        guarded(backend, "?, ?, ?, ?, ?, ?", uuid)
    );
    let [count, failed, success, logged, unlock] = values(row);
    let mut binds = vec![name(user), count, failed, success, logged, unlock.clone()];
    binds.extend(guard_binds(user, uuid, period));
    let sql = match backend {
        DbBackend::MySql => {
            let kept = "(last_admin_unlock IS NULL OR last_admin_unlock <= ?)";
            let set = COLUMNS
                .iter()
                .chain(["last_admin_unlock"].iter())
                .map(|column| format!("{column} = IF({kept}, ?, {column})"))
                .collect::<Vec<_>>()
                .join(", ");
            let assigned = binds[1..6].to_vec();
            for value in assigned {
                binds.push(unlock.clone());
                binds.push(value);
            }
            format!("{insert} ON DUPLICATE KEY UPDATE {set}")
        }
        DbBackend::Postgres | DbBackend::Sqlite => {
            let set = COLUMNS
                .iter()
                .chain(["last_admin_unlock"].iter())
                .map(|column| format!("{column} = excluded.{column}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{insert} ON CONFLICT (user_id) DO UPDATE SET {set} \
                 WHERE login_lockouts.last_admin_unlock IS NULL \
                 OR login_lockouts.last_admin_unlock <= excluded.last_admin_unlock"
            )
        }
    };
    Statement::from_sql_and_values(backend, numbered(backend, &sql), binds)
}

fn split_column(mark: SplitMark) -> i64 {
    i64::from_ne_bytes(mark.bits().to_ne_bytes())
}

fn split_of_column(value: i64) -> SplitMark {
    SplitMark::from_bits(u64::from_ne_bytes(value.to_ne_bytes()))
}

/// A start's id, verified by a finish on another server: count 0 for a new row, else that column.
pub(crate) fn split_statement(
    backend: DbBackend,
    period: &str,
    uuid: Option<&Uuid>,
    user: &UserId,
    mark: SplitMark,
) -> Statement {
    let id = Value::from(split_column(mark));
    let insert = format!(
        "INSERT INTO login_lockouts (user_id, fail_count, split_start) {}",
        guarded(backend, "?, 0, ?", uuid)
    );
    let mut binds = vec![name(user), id.clone()];
    binds.extend(guard_binds(user, uuid, period));
    let sql = match backend {
        DbBackend::MySql => {
            binds.push(id);
            format!("{insert} ON DUPLICATE KEY UPDATE split_start = ?")
        }
        DbBackend::Postgres | DbBackend::Sqlite => {
            format!(
                "{insert} ON CONFLICT (user_id) DO UPDATE SET split_start = excluded.split_start"
            )
        }
    };
    Statement::from_sql_and_values(backend, numbered(backend, &sql), binds)
}

pub(crate) fn unlock_statement(backend: DbBackend, user: &UserId, at: Timestamp) -> Statement {
    let at = to_naive(at);
    let upsert = match backend {
        DbBackend::MySql => "ON DUPLICATE KEY UPDATE",
        DbBackend::Postgres | DbBackend::Sqlite => "ON CONFLICT (user_id) DO UPDATE SET",
    };
    let sql = format!(
        "INSERT INTO login_lockouts (user_id, fail_count, last_admin_unlock) VALUES (?, 0, ?) \
         {upsert} fail_count = 0, last_admin_unlock = ?"
    );
    let values = vec![name(user), at.into(), at.into()];
    Statement::from_sql_and_values(backend, numbered(backend, &sql), values)
}

/// Whether a policy with a lockout threshold above 0 is linked to an OU, read in `conn`.
pub(crate) async fn threshold_linked_in(conn: &impl ConnectionTrait) -> Result<bool> {
    let links = model::OuPolicies::find()
        .filter(OuPoliciesColumn::PolicyId.is_not_null())
        .all(conn)
        .await?;
    let ids: Vec<i32> = links
        .into_iter()
        .filter_map(|link| link.policy_id)
        .collect();
    if ids.is_empty() {
        return Ok(false);
    }
    let policies = model::Policies::find()
        .filter(PoliciesColumn::Id.is_in(ids))
        .all(conn)
        .await?;
    for policy in policies {
        if sets_threshold(&decode_items(&policy.items)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) async fn period_in(conn: &impl ConnectionTrait) -> Result<String> {
    let found = system_config::Entity::find_by_id(PERIOD_KEY.to_owned())
        .one(conn)
        .await?;
    Ok(found.map_or_else(|| "0".to_owned(), |row| row.value))
}

/// The period under a shared lock, so a write and a zeroing never overlap.
async fn locked_period(conn: &impl ConnectionTrait) -> Result<String> {
    let backend = conn.get_database_backend();
    let (key, value, _) = quoted(backend);
    let lock = match backend {
        DbBackend::Postgres => " FOR SHARE",
        DbBackend::MySql => " LOCK IN SHARE MODE",
        DbBackend::Sqlite => "",
    };
    let sql = format!("SELECT {value} FROM system_config WHERE {key} = '{PERIOD_KEY}'{lock}");
    let found = conn.query_one(Statement::from_string(backend, sql)).await?;
    let text = found.and_then(|row| row.try_get_by_index::<String>(0).ok());
    Ok(text.unwrap_or_else(|| "0".to_owned()))
}

/// Raised in the statement, so two zeroings at once never take the same number.
async fn raise_period(conn: &impl ConnectionTrait) -> Result<String> {
    let backend = conn.get_database_backend();
    let (key, value, _) = quoted(backend);
    let (number, text) = match backend {
        DbBackend::MySql => ("SIGNED", "CHAR"),
        DbBackend::Postgres => ("BIGINT", "TEXT"),
        DbBackend::Sqlite => ("INTEGER", "TEXT"),
    };
    let sql = format!(
        "UPDATE system_config SET {value} = CAST(CAST({value} AS {number}) + 1 AS {text}) \
         WHERE {key} = '{PERIOD_KEY}'"
    );
    let raised = conn.execute(Statement::from_string(backend, sql)).await?;
    if raised.rows_affected() == 0 {
        let row = system_config::ActiveModel {
            key: Set(PERIOD_KEY.to_owned()),
            value: Set("1".to_owned()),
        };
        system_config::Entity::insert(row)
            .on_conflict(
                OnConflict::column(system_config::Column::Key)
                    .update_column(system_config::Column::Value)
                    .to_owned(),
            )
            .exec_without_returning(conn)
            .await?;
    }
    period_in(conn).await
}

/// The write that makes the first threshold effective starts a new period, then zeroes every
/// counting field, and changes nothing an administrator set.
pub(crate) struct CountingStart {
    was: bool,
}

impl CountingStart {
    pub(crate) async fn before(conn: &impl ConnectionTrait) -> Result<Self> {
        let was = threshold_linked_in(conn).await?;
        Ok(Self { was })
    }

    pub(crate) async fn after(self, conn: &impl ConnectionTrait) -> Result<bool> {
        if self.was || !threshold_linked_in(conn).await? {
            return Ok(false);
        }
        raise_period(conn).await?;
        let sql = "UPDATE login_lockouts SET fail_count = 0, lock_logged = NULL \
                   WHERE fail_count <> 0 OR lock_logged IS NOT NULL";
        conn.execute(Statement::from_string(conn.get_database_backend(), sql))
            .await?;
        Ok(true)
    }
}

fn row_of(found: model::login_lockouts::Model) -> LockRow {
    LockRow {
        fail_count: u32::try_from(found.fail_count).unwrap_or(0),
        last_failed: found.last_failed.map(from_naive),
        last_success: found.last_success.map(from_naive),
        last_admin_unlock: found.last_admin_unlock.map(from_naive),
        lock_logged: found.lock_logged.map(from_naive),
    }
}

#[async_trait]
impl LockStore for SqlBackendHandler {
    async fn read_lock(&self, user: &UserId) -> Result<Option<LockRow>> {
        let found = model::LoginLockouts::find_by_id(user.clone())
            .one(&self.sql_pool)
            .await?;
        Ok(found.map(row_of))
    }

    async fn read_locks(&self, since: Option<Timestamp>) -> Result<Vec<StoredLock>> {
        let mut query = model::LoginLockouts::find();
        if let Some(since) = since.map(to_naive) {
            query = query.filter(
                Condition::any()
                    .add(LoginLockoutsColumn::LastFailed.gte(since))
                    .add(LoginLockoutsColumn::LastSuccess.gte(since))
                    .add(LoginLockoutsColumn::LastAdminUnlock.gte(since))
                    .add(LoginLockoutsColumn::LockLogged.gte(since)),
            );
        }
        let found = query.all(&self.sql_pool).await?;
        let users: Vec<UserId> = found.iter().map(|row| row.user_id.clone()).collect();
        let mut accounts: HashMap<UserId, Uuid> = HashMap::new();
        for some in users.chunks(BATCH_LIMIT) {
            let pairs = model::User::find()
                .select_only()
                .column(UserColumn::UserId)
                .column(UserColumn::Uuid)
                .filter(UserColumn::UserId.is_in(some.to_vec()))
                .into_tuple::<(UserId, Uuid)>()
                .all(&self.sql_pool)
                .await?;
            accounts.extend(pairs);
        }
        Ok(found
            .into_iter()
            .map(|row| {
                let uuid = accounts.get(&row.user_id).cloned();
                (row.user_id.clone(), uuid, row_of(row))
            })
            .collect())
    }

    async fn read_lock_users(&self) -> Result<Vec<UserId>> {
        let found: Vec<UserId> = model::LoginLockouts::find()
            .select_only()
            .column(LoginLockoutsColumn::UserId)
            .into_tuple()
            .all(&self.sql_pool)
            .await?;
        Ok(found)
    }

    async fn read_split(&self, user: &UserId) -> Result<Option<SplitMark>> {
        let found = model::LoginLockouts::find_by_id(user.clone())
            .one(&self.sql_pool)
            .await?;
        Ok(found.and_then(|row| row.split_start).map(split_of_column))
    }

    async fn read_period(&self) -> Result<String> {
        period_in(&self.sql_pool).await
    }

    async fn prune_codes(&self) -> Result<u64> {
        self.prune_totp_steps().await
    }

    async fn read_recording(&self) -> Result<Option<Timestamp>> {
        recording_in(&self.sql_pool).await
    }

    async fn write_recording(&self, live: bool, at: Timestamp) -> Result<Option<Timestamp>> {
        move_recording(&self.sql_pool, live, at).await
    }

    async fn write_success(&self, user: &UserId, at: Timestamp) -> Result<()> {
        let backend = self.sql_pool.get_database_backend();
        self.sql_pool
            .execute(success_statement(backend, user, at))
            .await?;
        Ok(())
    }

    /// What was stored is told by reading it back: an affected-row count says nothing about a
    /// kept row on every backend.
    async fn write_locks(&self, period: &str, writes: &[LockWrite]) -> Result<Written> {
        let txn = self.sql_pool.begin().await?;
        let backend = txn.get_database_backend();
        let current = locked_period(&txn).await?;
        let users: Vec<UserId> = writes.iter().map(|write| write.user.clone()).collect();
        if current == period {
            for write in writes {
                let uuid = write.uuid.as_ref();
                if let Some(row) = &write.row {
                    let put = put_statement(backend, period, uuid, &write.user, row);
                    txn.execute(put).await?;
                }
                if let Some(mark) = write.split {
                    let split = split_statement(backend, period, uuid, &write.user, mark);
                    txn.execute(split).await?;
                }
            }
        }
        let stored: HashMap<UserId, model::login_lockouts::Model> = model::LoginLockouts::find()
            .filter(LoginLockoutsColumn::UserId.is_in(users.clone()))
            .all(&txn)
            .await?
            .into_iter()
            .map(|found| (found.user_id.clone(), found))
            .collect();
        let accounts: HashMap<UserId, Uuid> = model::User::find()
            .select_only()
            .column(UserColumn::UserId)
            .column(UserColumn::Uuid)
            .filter(UserColumn::UserId.is_in(users))
            .into_tuple::<(UserId, Uuid)>()
            .all(&txn)
            .await?
            .into_iter()
            .collect();
        txn.commit().await?;
        let mut written = Written {
            period: current,
            ..Written::default()
        };
        for write in writes {
            let user = &write.user;
            let same = accounts
                .get(user)
                .is_some_and(|uuid| write.uuid.as_ref().is_none_or(|held| held == uuid));
            if !same {
                written.kept.push((user.clone(), None));
                continue;
            }
            let found = stored.get(user);
            let row = found.cloned().map(row_of);
            if write.row.is_some() && row != write.row {
                written.kept.push((user.clone(), row));
            }
            let split = found.and_then(|found| found.split_start);
            let id = write.split.map(split_column);
            if id.is_some() && split != id {
                written.split_kept.push(user.clone());
            }
        }
        Ok(written)
    }
}

/// The unlock and its row in one transaction; the host tool has a pool and no handler.
pub async fn unlock_login_on(
    pool: &DbConnection,
    user: &UserId,
    at: Timestamp,
    row: LogEvent,
) -> Result<()> {
    let txn = pool.begin().await?;
    if model::User::find_by_id(user.clone())
        .one(&txn)
        .await?
        .is_none()
    {
        return Err(DomainError::EntityNotFound(format!("No user named {user}")));
    }
    txn.execute(unlock_statement(txn.get_database_backend(), user, at))
        .await?;
    model::Logs::insert(to_active_model(row))
        .exec_without_returning(&txn)
        .await?;
    txn.commit().await?;
    Ok(())
}

#[async_trait]
impl LockoutBackendHandler for SqlBackendHandler {
    async fn unlock_user(&self, user_id: &UserId) -> Result<()> {
        let at = lock_clock();
        let detail = Some(UNLOCKED_BY_ADMIN);
        let row = logging::event(LogKind::AccountUnlock, Some(user_id.as_str()), true, detail);
        unlock_login_on(&self.sql_pool, user_id, at, row.clone()).await?;
        logging::print(&row);
        self.lockout.unlocked(user_id, at);
        Ok(())
    }

    async fn reenable_user(&self, user_id: &UserId) -> Result<()> {
        let detail = Some(REENABLED_BY_ADMIN);
        let row = logging::event(
            LogKind::AccountReenable,
            Some(user_id.as_str()),
            true,
            detail,
        );
        reenable_user_on(&self.sql_pool, user_id, lock_clock(), row.clone()).await?;
        logging::print(&row);
        self.user_written(user_id).await;
        Ok(())
    }

    async fn note_sign_in(&self, user_id: &UserId) {
        self.note_activity(user_id, lock_clock()).await;
    }

    async fn sign_in_state(&self, user_id: &UserId) -> Result<SignInState> {
        let now = lock_clock();
        let lock = self.lock_state(user_id).await?;
        let lock = lock.filter(|lock| lock.locked(now));
        let idle = inactive_since(self, self.policy_cache, user_id, now).await?;
        Ok(SignInState {
            locked: lock.is_some(),
            locked_until: lock.and_then(|lock| lock.row.lock_end(lock.policy)),
            inactive_since: idle,
        })
    }
}

impl SqlBackendHandler {
    pub(crate) async fn lock_state(&self, user: &UserId) -> Result<Option<LockState>> {
        self.lockout.state(self, self.policy_cache, user).await
    }

    pub(crate) fn lock_unreadable(user: &UserId, kind: LogKind, e: DomainError) -> DomainError {
        warn_limited!(r#"The lockout of "{user}" could not be read: {e}"#);
        let detail = format!("policy: {UNREADABLE}");
        logging::record_as(Some(user), kind, None, false, Some(&detail));
        invalid_credentials(user)
    }

    /// The refusal's own row; a refusal counts nothing and logs no lock.
    pub(crate) fn refuse_locked(&self, user: &UserId, kind: LogKind) {
        debug!(r#"Login attempt refused for "{user}": {LOCKED_OUT}"#);
        logging::record_as(Some(user), kind, None, false, Some(LOCKED_OUT));
    }

    pub(crate) async fn carry_lock(&self, lock: &LockState, step: Step, door: Door) {
        if step.lock_logged {
            record_account_lock(&lock.user, door);
        }
        self.lockout.carry(self, &lock.user, step).await;
    }

    pub(crate) async fn count_failure(&self, lock: Option<&LockState>, door: Door, at: Timestamp) {
        if let Some(lock) = lock {
            self.carry_lock(lock, self.lockout.failure(lock, at), door)
                .await;
        }
    }

    pub(crate) async fn count_success(&self, lock: Option<&LockState>, door: Door, at: Timestamp) {
        if let Some(lock) = lock {
            self.carry_lock(lock, self.lockout.success(lock, at), door)
                .await;
        }
    }

    pub(crate) async fn count_nothing(&self, lock: Option<&LockState>, door: Door, at: Timestamp) {
        if let Some(lock) = lock {
            self.carry_lock(lock, self.lockout.unchanged(lock, at), door)
                .await;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::{
        get_initialized_db, insert_group, insert_membership, insert_user_no_password,
    };
    use crate::sql_mfa_handler::{PinnedClock, pin_clock};
    use crate::sql_tables::init_table;
    use lldap_auth::login;
    use lldap_auth::opaque::{self, server::generate_random_private_key};
    use lldap_domain::requests::{CreateUserRequest, UpdateUserRequest};
    use lldap_domain::types::{Attribute, LoginOutcome};
    use lldap_domain_handlers::enforcement::{
        Attempt, INACTIVITY_DAYS, PolicyCache, Refusal, admit, admit_at_kdc_with,
        default_item_checks, fill_policy_cache,
    };
    use lldap_domain_handlers::handler::{
        BindRequest, LoginHandler, MfaBackendHandler, PolicyBackendHandler, UserBackendHandler,
    };
    use lldap_domain_handlers::instant::{SignedDuration, days};
    use lldap_domain_handlers::lockout::{
        DURATION, Lockout, LockoutPolicy, THRESHOLD, lock_detail,
    };
    use lldap_domain_handlers::logging::{Protocol, RequestMeta, with_request, without_session};
    use lldap_domain_handlers::mfa::{
        MFA_DISABLED_GROUP, MfaPolicy, MfaRequirement, MfaResetReason,
    };
    use lldap_domain_handlers::policies::{CreatePolicyRequest, PolicyId, UpdatePolicyRequest};
    use lldap_mfa::{
        TOTP_MAX_ATTEMPTS_PER_STEP, TOTP_STEP_SECS, TOTP_TOO_MANY_ATTEMPTS, format_code, totp_code,
    };
    use lldap_opaque_handler::{OpaqueHandler, register_password};
    use lldap_test_utils::enforcement::EnforcementGuard;
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    pub(crate) const RIGHT: &str = "Right-Pass-1";

    pub(crate) fn own(handler: SqlBackendHandler) -> SqlBackendHandler {
        let lockout: &'static Lockout = Box::leak(Box::default());
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        handler.with_lockout(lockout).with_policy_cache(cache)
    }

    pub(crate) async fn handler() -> SqlBackendHandler {
        own(SqlBackendHandler::new(
            generate_random_private_key(),
            get_initialized_db().await,
        ))
    }

    /// Two servers on one database, one key between them.
    fn servers(pool: &DbConnection) -> (SqlBackendHandler, SqlBackendHandler) {
        let key = generate_random_private_key();
        (
            own(SqlBackendHandler::new(key.clone(), pool.clone())),
            own(SqlBackendHandler::new(key, pool.clone())),
        )
    }

    pub(crate) async fn user_in(handler: &SqlBackendHandler, user: &str, ou: &str) {
        let request = CreateUserRequest {
            user_id: UserId::new(user),
            email: format!("{user}@example.com").into(),
            attributes: vec![Attribute {
                name: "ou".into(),
                value: ou.to_owned().into(),
            }],
            ..Default::default()
        };
        handler.create_user(request).await.unwrap();
        register_password(handler, UserId::new(user), RIGHT.as_bytes())
            .await
            .unwrap();
    }

    async fn threshold(handler: &SqlBackendHandler, ou: &str, value: &str) -> PolicyId {
        let request = CreatePolicyRequest {
            name: format!("lock {ou}"),
            description: String::new(),
            items: [
                (THRESHOLD.to_owned(), value.to_owned()),
                (DURATION.to_owned(), "0".to_owned()),
            ]
            .into(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy(ou, id).await.unwrap();
        id
    }

    pub(crate) async fn policy_on(
        handler: &SqlBackendHandler,
        ou: &str,
        items: &[(&str, &str)],
    ) -> PolicyId {
        let pairs = items
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()));
        let request = CreatePolicyRequest {
            name: format!("on {ou}"),
            description: String::new(),
            items: pairs.collect(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy(ou, id).await.unwrap();
        id
    }

    async fn follow(handler: &SqlBackendHandler) {
        let cache = handler.policy_cache;
        handler
            .lockout
            .follow_policies(handler, cache)
            .await
            .unwrap();
    }

    pub(crate) async fn bind_as(
        handler: &SqlBackendHandler,
        user: &str,
        password: &str,
    ) -> Result<()> {
        let request = BindRequest {
            name: UserId::new(user),
            password: password.to_owned(),
        };
        handler.bind(request).await
    }

    pub(crate) async fn bind(handler: &SqlBackendHandler, user: &str, password: &str) -> bool {
        bind_as(handler, user, password).await.is_ok()
    }

    async fn stored(handler: &SqlBackendHandler, user: &str) -> Option<u32> {
        let row = handler.read_lock(&UserId::new(user)).await.unwrap();
        row.map(|row| row.fail_count)
    }

    fn viewed(handler: &SqlBackendHandler, user: &str) -> u32 {
        let row = handler.lockout.row(&UserId::new(user));
        row.map_or(0, |row| row.fail_count)
    }

    fn judged(handler: &SqlBackendHandler, user: &str) -> u32 {
        let row = handler.lockout.effective(&UserId::new(user));
        row.map_or(0, |row| row.fail_count)
    }

    pub(crate) type Started = (
        opaque::client::login::ClientLogin,
        login::ServerLoginStartResponse,
    );

    pub(crate) async fn start(handler: &SqlBackendHandler, user: &str, password: &str) -> Started {
        let start = opaque::client::login::start_login(password, &mut rand::rngs::OsRng).unwrap();
        let request = login::ClientLoginStartRequest {
            username: UserId::new(user),
            login_start_request: start.message,
        };
        (start.state, handler.login_start(request).await.unwrap())
    }

    /// None when the client cannot finish, as for a wrong password: the web app sends nothing.
    pub(crate) fn finish_request(
        (state, started): Started,
        password: &str,
        code: Option<&str>,
    ) -> Option<login::ClientLoginFinishRequest> {
        let finished = opaque::client::login::finish_login(
            state,
            password.as_bytes(),
            started.credential_response,
            &mut rand::rngs::OsRng,
        )
        .ok()?;
        Some(login::ClientLoginFinishRequest {
            server_data: started.server_data,
            credential_finalization: finished.message,
            totp_code: code.map(str::to_owned),
            enrollment_proof: None,
            session: None,
        })
    }

    pub(crate) async fn web(
        handler: &SqlBackendHandler,
        user: &str,
        password: &str,
        code: Option<&str>,
    ) -> std::result::Result<LoginOutcome, &'static str> {
        let started = start(handler, user, password).await;
        let request = finish_request(started, password, code).ok_or("client")?;
        handler.login_finish(request).await.map_err(|_| "server")
    }

    pub(crate) fn rows(
        log: &LogGuard,
        kinds: &[LogKind],
    ) -> Vec<(LogKind, Option<String>, Option<String>)> {
        let events = log.recorder().take_events().into_iter();
        events
            .filter(|e| kinds.contains(&e.kind))
            .map(|e| (e.kind, e.target.or(e.actor), e.detail))
            .collect()
    }

    fn write(user: &UserId, row: LockRow) -> LockWrite {
        LockWrite {
            user: user.clone(),
            uuid: None,
            row: Some(row),
            split: None,
        }
    }

    fn time(seconds: i64, micros: i64) -> Timestamp {
        let at = 1_700_000_000_000_000 + seconds * 1_000_000 + micros;
        lldap_domain_handlers::lockout::time_of_micros(at).unwrap()
    }

    /// Each statement, on any backend: a row stored as given, an unlock never undone, nothing
    /// for a name that is no user or from an older period.
    pub(crate) async fn lockout_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        insert_user_no_password(&handler, "e1lane").await;
        let user = UserId::new("e1lane");
        let put = async |row: LockRow| {
            let written = handler.write_locks("0", &[write(&user, row)]).await;
            written.unwrap().kept
        };
        let read = async || handler.read_lock(&user).await.unwrap();
        let first = LockRow {
            fail_count: 2,
            last_failed: Some(time(1, 123_456)),
            ..LockRow::default()
        };
        assert_eq!((put(first).await, read().await), (vec![], Some(first)));
        let logged = LockRow {
            fail_count: 3,
            last_failed: Some(time(2, 1)),
            lock_logged: Some(time(2, 1)),
            last_success: Some(time(0, 9)),
            ..LockRow::default()
        };
        assert_eq!((put(logged).await, read().await), (vec![], Some(logged)));
        let unlock = time(3, 654_321);
        let backend = pool.get_database_backend();
        pool.execute(unlock_statement(backend, &user, unlock))
            .await
            .expect("unlock");
        let unlocked = logged.unlocked(unlock);
        assert_eq!(read().await, Some(unlocked));
        let late = LockRow {
            fail_count: 4,
            ..logged
        };
        assert_eq!(
            (put(late).await, read().await),
            (vec![(user.clone(), Some(unlocked))], Some(unlocked)),
            "a row from before the unlock does not undo it, and the read-back says so"
        );
        let after = unlocked.failed(time(4, 0));
        assert_eq!((put(after).await, read().await), (vec![], Some(after)));
        let since = |s| handler.read_locks(Some(time(s, 0)));
        let account = Some(handler.get_user_details(&user).await.unwrap().uuid);
        assert_eq!(
            since(4).await.unwrap(),
            vec![(user.clone(), account, after)]
        );
        assert_eq!(since(5).await.unwrap(), vec![]);
        let nobody = UserId::new("e1nobody");
        let next = after.failed(time(5, 0));
        let both = [write(&nobody, first), write(&user, next)];
        let written = handler.write_locks("0", &both).await.unwrap();
        assert_eq!(
            (written.kept, read().await),
            (vec![(nobody, None)], Some(next)),
            "a name that is no user stores nothing and holds up nothing"
        );
        let other = Uuid::from_name_and_date("e1lane", &to_naive(time(0, 0)));
        let renamed = LockWrite {
            uuid: Some(other),
            ..write(&user, first)
        };
        let written = handler.write_locks("0", &[renamed]).await.unwrap();
        assert_eq!(
            (written.kept, read().await),
            (vec![(user.clone(), None)], Some(next)),
            "a write for another account of the same name stores nothing"
        );
        let mark = SplitMark::of(u64::MAX - 7, true);
        let split = |mark| LockWrite {
            row: None,
            split: Some(mark),
            ..write(&user, first)
        };
        let written = handler.write_locks("0", &[split(mark)]).await.unwrap();
        assert_eq!(
            (
                written,
                read().await,
                handler.read_split(&user).await.unwrap()
            ),
            (
                Written {
                    period: "0".to_owned(),
                    ..Written::default()
                },
                Some(next),
                Some(mark)
            ),
            "a start's id is stored in its own column, and the row is left as it was"
        );
        let txn = pool.begin().await.unwrap();
        assert_eq!(raise_period(&txn).await.unwrap(), "1");
        txn.commit().await.unwrap();
        let older = handler
            .write_locks("0", &[write(&user, first), split(SplitMark::of(3, false))])
            .await
            .unwrap();
        assert_eq!(
            (&older.split_kept, handler.read_split(&user).await.unwrap()),
            (&vec![user.clone()], Some(mark)),
            "the old-period split write is reported in split_kept and stores nothing"
        );
        assert_eq!(
            (older, handler.read_period().await.unwrap()),
            (
                Written {
                    kept: vec![(user.clone(), Some(next))],
                    split_kept: vec![user.clone()],
                    period: "1".to_owned()
                },
                "1".to_owned()
            ),
            "a write from an older period stores nothing"
        );
        assert_eq!(handler.read_split(&user).await.unwrap(), Some(mark));
        assert_eq!(handler.read_lock_users().await.unwrap(), vec![user.clone()]);
        handler.delete_user(&user).await.unwrap();
        assert_eq!(
            handler.read_locks(None).await.unwrap(),
            vec![],
            "the row goes with its user"
        );
    }

    /// Two servers: a user deleted on one while the other owes it a write.
    pub(crate) async fn gone_user_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let (one, two) = servers(pool);
        user_in(&one, "e1gone", "e1goneou").await;
        user_in(&one, "e1stays", "e1goneou").await;
        threshold(&one, "e1lockedou", "3").await;
        follow(&two).await;
        assert!(!bind(&two, "e1gone", "nope").await);
        assert!(!bind(&two, "e1stays", "nope").await);
        let gone = UserId::new("e1gone");
        assert!(two.lockout.pending(&gone), "owed on the second server");
        one.delete_user(&gone).await.unwrap();
        assert_eq!(two.lockout.drain(&two).await, 2);
        assert_eq!(
            (
                stored(&two, "e1stays").await,
                two.lockout.row(&gone),
                two.lockout.pending(&gone),
                two.lockout.outage().is_none()
            ),
            (Some(1), None, false, true),
            "the other user's row is stored; the gone one is forgotten, not retried"
        );
    }

    /// Two servers: each sign-in starts on one and finishes on the other.
    pub(crate) async fn split_login_lane(pool: &DbConnection, timer: bool) {
        let (_clock, at) = pinned();
        init_table(pool).await.expect("init");
        let (a, b) = servers(pool);
        let (a, b) = (
            a.with_mfa_policy(MfaPolicy::Enrolled),
            b.with_mfa_policy(MfaPolicy::Enrolled),
        );
        user_in(&a, "e1split", "e1splitou").await;
        threshold(&a, "e1splitou", "3").await;
        follow(&b).await;
        for sign_in in 0..4 {
            let request = finish_request(start(&a, "e1split", RIGHT).await, RIGHT, None);
            let outcome = b.login_finish(request.unwrap()).await;
            assert!(outcome.is_ok(), "sign-in {sign_in} on the second server");
            a.lockout.write_all_now(&a).await;
            assert_eq!(
                stored(&a, "e1split").await,
                Some(0),
                "sign-in {sign_in}: the start the first server held is dropped by its id"
            );
        }
        for (case, second_start, second_finish) in [
            ("aa", &a, &a),
            ("ab", &a, &b),
            ("bb", &b, &b),
            ("ba", &b, &a),
        ] {
            let user = format!("e1two{case}");
            user_in(&a, &user, "e1splitou").await;
            let seed = enroll(&a, &user, at).await;
            let timed =
                (timer && case == "ab").then(|| a.lockout.run(Arc::new(a.clone()), a.policy_cache));
            let first = finish_request(start(&a, &user, RIGHT).await, RIGHT, None);
            assert_eq!(
                b.login_finish(first.unwrap()).await.unwrap(),
                LoginOutcome::TotpRequired,
                "{case}: code required on the second server"
            );
            let ([code, _], _) = codes(&seed, at);
            let started = start(second_start, &user, RIGHT).await;
            let second = finish_request(started, RIGHT, Some(code.as_str()));
            let finished = second_finish.login_finish(second.unwrap()).await;
            assert!(
                matches!(finished, Ok(LoginOutcome::Authenticated { .. })),
                "{case}: {finished:?}"
            );
            if let Some(running) = timed {
                b.lockout.write_all_now(&b).await;
                tokio::time::sleep(Duration::from_secs(11)).await;
                let held = || {
                    let user = UserId::new(&user);
                    a.lockout.overlays(&user) + usize::from(a.lockout.pending(&user))
                };
                let settled = Instant::now() + Duration::from_secs(3);
                while held() > 0 && Instant::now() < settled {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                running.abort();
                let _ = running.await;
                assert_eq!(held(), 0, "{case}: both starts expired on the timer");
            }
            a.lockout.write_all_now(&a).await;
            b.lockout.write_all_now(&b).await;
            assert_eq!(
                stored(&a, &user).await.unwrap_or(0),
                0,
                "{case}: the first server's start, the second's code required, then the code step"
            );
        }
        user_in(&a, "e1between", "e1splitou").await;
        enroll(&a, "e1between", at).await;
        let first = finish_request(start(&a, "e1between", RIGHT).await, RIGHT, None);
        assert_eq!(
            b.login_finish(first.unwrap()).await.unwrap(),
            LoginOutcome::TotpRequired
        );
        assert_eq!(web(&a, "e1between", "nope", None).await, Err("client"));
        b.lockout.write_all_now(&b).await;
        a.lockout.write_all_now(&a).await;
        assert_eq!(
            stored(&a, "e1between").await,
            Some(1),
            "a wrong start between the two steps is not dropped by an id whose sign-in did not \
             complete"
        );
        user_in(&a, "e1alone", "e1splitou").await;
        let _ = start(&a, "e1alone", RIGHT).await;
        a.lockout.write_all_now(&a).await;
        assert_eq!(
            stored(&a, "e1alone").await,
            Some(1),
            "control: a start that nobody finished is counted"
        );
    }

    /// A count write that meets the zeroing waits for it, then stores nothing.
    pub(crate) async fn period_overlap_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        insert_user_no_password(&handler, "e1overlap").await;
        let user = UserId::new("e1overlap");
        let four = LockRow::default()
            .failed(time(1, 0))
            .failed(time(2, 0))
            .failed(time(3, 0))
            .failed(time(4, 0));
        handler
            .write_locks("0", &[write(&user, four)])
            .await
            .unwrap();
        let zeroing = pool.begin().await.unwrap();
        raise_period(&zeroing).await.unwrap();
        zeroing
            .execute(Statement::from_string(
                zeroing.get_database_backend(),
                "UPDATE login_lockouts SET fail_count = 0".to_owned(),
            ))
            .await
            .unwrap();
        let late = {
            let (handler, user) = (handler.clone(), user.clone());
            let five = four.failed(time(5, 0));
            tokio::spawn(async move { handler.write_locks("0", &[write(&user, five)]).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!late.is_finished(), "the write waits for the zeroing");
        zeroing.commit().await.unwrap();
        let written = late.await.unwrap().unwrap();
        assert_eq!(
            (
                written.period,
                handler
                    .read_lock(&user)
                    .await
                    .unwrap()
                    .map(|row| row.fail_count)
            ),
            ("1".to_owned(), Some(0)),
            "the old period's count does not land after the zeroing"
        );
    }

    #[tokio::test]
    async fn test_each_statement_stores_the_row_as_it_stands_on_sqlite() {
        lockout_lane(&get_initialized_db().await).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_a_user_deleted_on_one_server_while_another_owes_it_a_write_on_sqlite() {
        gone_user_lane(&get_initialized_db().await).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_starts_on_one_server_and_finishes_on_another_never_lock_the_user_on_sqlite() {
        split_login_lane(&get_initialized_db().await, false).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_a_refusal_after_a_good_code_on_another_server_settles_the_first_servers_start() {
        use lldap_domain_handlers::enforcement::{ItemCheck, UserState, set_item_checks};
        use lldap_domain_handlers::lockout::LockoutCheck;
        struct RefusedWithTheCode;
        impl ItemCheck for RefusedWithTheCode {
            fn key(&self) -> &'static str {
                "login-hours"
            }
            fn allows(&self, attempt: &Attempt<'_>, _: &str, _: &UserState) -> bool {
                !attempt.second_factor
            }
        }
        let (_clock, at) = pinned();
        let pool = get_initialized_db().await;
        let (a, b) = servers(&pool);
        let (a, b) = (
            a.with_mfa_policy(MfaPolicy::Enrolled),
            b.with_mfa_policy(MfaPolicy::Enrolled),
        );
        let users = ["q33settled", "q33counted"];
        for user in users {
            user_in(&a, user, "q33ou").await;
        }
        let items = [
            (THRESHOLD, "3"),
            (DURATION, "0"),
            ("login-hours", "mon 08:00-18:00"),
        ];
        policy_on(&a, "q33ou", &items).await;
        follow(&b).await;
        let seeds = [
            enroll(&a, users[0], at).await,
            enroll(&a, users[1], at).await,
        ];
        let _guard = EnforcementGuard::default_checks();
        let checks: Vec<Arc<dyn ItemCheck>> =
            vec![Arc::new(LockoutCheck), Arc::new(RefusedWithTheCode)];
        set_item_checks(checks.into());
        let refused_on_b = async |user: &str, seed: &[u8]| {
            let ([code, _], _) = codes(seed, at);
            let started = start(&a, user, RIGHT).await;
            let request = finish_request(started, RIGHT, Some(code.as_str())).unwrap();
            let answered = b.login_finish(request).await.map(drop);
            (
                answered.map_err(|e| e.to_string()),
                b.lockout.pending(&UserId::new(user)),
            )
        };
        let settled = refused_on_b(users[0], &seeds[0][..]).await;
        b.lockout.drain(&b).await;
        a.lockout.write_all_now(&a).await;
        let counted = refused_on_b(users[1], &seeds[1][..]).await;
        a.lockout.write_all_now(&a).await;
        b.lockout.drain(&b).await;
        let failed =
            Err(DomainError::from(opaque::AuthenticationError::failed_proof()).to_string());
        assert_eq!(
            (settled, counted),
            ((failed.clone(), true), (failed, true)),
            "the second server answers the failed proof at once, its split owed to the run loop"
        );
        assert_eq!(
            (
                stored(&a, users[0]).await.unwrap_or(0),
                stored(&a, users[1]).await
            ),
            (0, Some(1)),
            "written before the first server folds its start: nothing counted; written after: \
             the start counts as any start no finish took"
        );
    }

    #[tokio::test]
    async fn test_a_write_queued_behind_the_zeroing_on_sqlites_one_connection_stores_nothing() {
        period_overlap_lane(&get_initialized_db().await).await;
    }

    /// Two zeroings at once each take their own period number.
    pub(crate) async fn period_raise_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let before: u64 = period_in(pool).await.unwrap().parse().unwrap();
        let first = pool.begin().await.unwrap();
        let raised = raise_period(&first).await.unwrap();
        let second = {
            let pool = pool.clone();
            tokio::spawn(async move {
                let txn = pool.begin().await.unwrap();
                let raised = raise_period(&txn).await.unwrap();
                txn.commit().await.unwrap();
                raised
            })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        first.commit().await.unwrap();
        assert_eq!(
            (
                raised,
                second.await.unwrap(),
                period_in(pool).await.unwrap()
            ),
            (
                (before + 1).to_string(),
                (before + 2).to_string(),
                (before + 2).to_string()
            ),
            "the second zeroing takes the next number, not the same one"
        );
    }

    #[tokio::test]
    async fn test_two_zeroings_at_once_take_two_period_numbers_on_sqlite() {
        period_raise_lane(&get_initialized_db().await).await;
    }

    #[test]
    fn test_each_backend_gets_its_own_upsert() {
        let row = LockRow::default();
        let user = UserId::new("bob");
        let sql = |backend| put_statement(backend, "7", None, &user, &row);
        let (sqlite, postgres, mysql) = (
            sql(DbBackend::Sqlite),
            sql(DbBackend::Postgres),
            sql(DbBackend::MySql),
        );
        let only_for_users = "WHERE EXISTS (SELECT 1 FROM users WHERE users.user_id = ?)";
        assert!(
            sqlite.sql.contains(only_for_users)
                && sqlite
                    .sql
                    .contains(r#""key" = 'lockout_period'), '0') = ?"#)
                && sqlite
                    .sql
                    .contains("ON CONFLICT (user_id) DO UPDATE SET fail_count = excluded"),
            "{}",
            sqlite.sql
        );
        assert!(
            postgres
                .sql
                .contains("SELECT $1, $2, $3, $4, $5, $6 WHERE EXISTS")
                && postgres.sql.contains("users.user_id = $7)")
                && postgres.sql.contains("'0') = $8"),
            "{}",
            postgres.sql
        );
        assert!(
            mysql.sql.contains("FROM DUAL WHERE EXISTS")
                && mysql.sql.contains("`key` = 'lockout_period'")
                && mysql.sql.ends_with(
                    "last_admin_unlock = IF((last_admin_unlock IS NULL OR last_admin_unlock \
                     <= ?), ?, last_admin_unlock)"
                ),
            "{}",
            mysql.sql
        );
        let binds = |s: &Statement| s.values.as_ref().map_or(0, |v| v.0.len());
        assert_eq!((binds(&sqlite), binds(&mysql)), (8, 18));
        let period = sqlite.values.as_ref().map(|v| v.0[7].clone());
        assert_eq!(period, Some(Value::from("7".to_owned())));
        let uuid = Uuid::from_name_and_date("bob", &to_naive(time(0, 0)));
        let same = put_statement(DbBackend::Sqlite, "7", Some(&uuid), &user, &row);
        assert!(
            same.sql.contains("users.user_id = ? AND users.uuid = ?)") && binds(&same) == 9,
            "{}",
            same.sql
        );
        let split = |backend| split_statement(backend, "7", None, &user, SplitMark::of(5, true));
        let (sqlite, mysql) = (split(DbBackend::Sqlite), split(DbBackend::MySql));
        assert!(
            sqlite.sql.starts_with(
                "INSERT INTO login_lockouts (user_id, fail_count, split_start) SELECT ?, 0, ?"
            ) && sqlite
                .sql
                .ends_with("DO UPDATE SET split_start = excluded.split_start")
                && !sqlite.sql.contains("last_admin_unlock"),
            "{}",
            sqlite.sql
        );
        assert!(
            mysql
                .sql
                .ends_with("ON DUPLICATE KEY UPDATE split_start = ?")
                && binds(&mysql) == 5,
            "{}",
            mysql.sql
        );
    }

    async fn sign_in_states(h: &SqlBackendHandler, users: &[&str]) -> Vec<SignInState> {
        let mut states = Vec::new();
        for user in users {
            states.push(h.sign_in_state(&UserId::new(user)).await.unwrap());
        }
        states
    }

    #[tokio::test]
    #[serial]
    async fn test_the_sign_in_state_says_locked_until_inactive_since_or_neither() {
        let guard = EnforcementGuard::default_checks();
        let h = handler().await;
        let users = ["e7lock", "e7hold", "e7idle"];
        for user in users {
            user_in(&h, user, &format!("{user}ou")).await;
        }
        let t = Timestamp::from_second(Timestamp::now().as_second() + 60).unwrap();
        guard.pin_clock(t);
        policy_on(&h, "e7lockou", &[(THRESHOLD, "2"), (DURATION, "600")]).await;
        policy_on(&h, "e7holdou", &[(THRESHOLD, "1"), (DURATION, "0")]).await;
        policy_on(&h, "e7idleou", &[(INACTIVITY_DAYS, "1")]).await;
        for (user, wrong) in [("e7lock", 2), ("e7hold", 1)] {
            for _ in 0..wrong {
                assert!(!bind(&h, user, "nope-7").await, "{user}");
            }
        }
        let at_t = sign_in_states(&h, &users).await;
        guard.pin_clock(t + days(2));
        let two_days_on = sign_in_states(&h, &users).await;
        h.unlock_user(&UserId::new("e7hold")).await.unwrap();
        h.reenable_user(&UserId::new("e7idle")).await.unwrap();
        let after_both = sign_in_states(&h, &users).await;
        let neither = SignInState::default();
        let locked = |seconds: Option<i64>| SignInState {
            locked: true,
            locked_until: seconds.map(|seconds| t + SignedDuration::from_secs(seconds)),
            ..neither
        };
        let inactive = SignInState {
            inactive_since: Some(t + days(1)),
            ..neither
        };
        assert_eq!(
            (at_t, two_days_on, after_both),
            (
                vec![locked(Some(600)), locked(None), neither],
                vec![neither, locked(None), inactive],
                vec![neither, neither, neither],
            ),
            "a lock ends 600 s after the last failure or holds until an unlock; inactive one day \
             after the item went live; each admin action clears its state"
        );
        let nobody = h.sign_in_state(&UserId::new("e7nobody")).await;
        assert!(
            matches!(nobody, Err(DomainError::EntityNotFound(_))),
            "{nobody:?}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_unlock_by_another_server_is_taken_at_the_doors_within_a_second() {
        let pool = get_initialized_db().await;
        let (here, there) = servers(&pool);
        user_in(&here, "e1second", "e1secondou").await;
        threshold(&there, "e1secondou", "1").await;
        assert!(!bind(&there, "e1second", "nope").await);
        there.lockout.write_all_now(&there).await;
        assert!(
            !bind(&there, "e1second", RIGHT).await,
            "locked; the lock looked at"
        );
        here.unlock_user(&UserId::new("e1second")).await.unwrap();
        let inside = bind(&there, "e1second", RIGHT).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let past = bind(&there, "e1second", RIGHT).await;
        assert_eq!(
            (inside, past),
            (false, true),
            "inside the second the held lock answers; the first attempt past it takes the unlock"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_unlock_stamps_the_servers_clock_with_its_row_and_a_second_view_follows() {
        let pool = get_initialized_db().await;
        let (here, there) = servers(&pool);
        user_in(&here, "e1unlock", "e1unlockou").await;
        let user = UserId::new("e1unlock");
        let counted = LockRow::default().failed(time(1, 0)).failed(time(2, 0));
        here.write_locks("0", &[write(&user, counted)])
            .await
            .unwrap();
        assert_eq!(there.lockout.refresh(&there).await.unwrap(), 1);
        assert_eq!(
            viewed(&there, "e1unlock"),
            2,
            "another writer's row, at the refresh"
        );
        let before = lock_clock();
        here.unlock_user(&user).await.unwrap();
        let after = lock_clock();
        let row = here.read_lock(&user).await.unwrap().unwrap();
        let at = row.last_admin_unlock.unwrap();
        assert!(before <= at && at <= after, "{before} {at} {after}");
        assert_eq!((row.fail_count, viewed(&here, "e1unlock")), (0, 0));
        there.lockout.refresh(&there).await.unwrap();
        assert_eq!(
            viewed(&there, "e1unlock"),
            0,
            "the unlock reaches the other view"
        );
        let unlock_rows = model::Logs::find()
            .filter(model::LogsColumn::Kind.eq("account_unlock"))
            .all(&pool)
            .await
            .unwrap();
        let unlock_rows: Vec<_> = unlock_rows
            .into_iter()
            .map(|row| (row.target, row.detail, row.success))
            .collect();
        let expected = (
            Some("e1unlock".to_owned()),
            Some(UNLOCKED_BY_ADMIN.to_owned()),
            true,
        );
        assert_eq!(unlock_rows, vec![expected]);
        let nobody = here.unlock_user(&UserId::new("e1nobody")).await;
        assert!(nobody.is_err());
        assert_eq!(
            here.read_lock(&UserId::new("e1nobody")).await.unwrap(),
            None
        );
    }

    #[test]
    #[serial]
    fn test_the_guards_clock_reaches_every_attempt_and_the_lockout_until_it_drops() {
        let bob = UserId::new("q7clock");
        let pinned = Timestamp::from_second(4_102_444_800).unwrap();
        let guard = EnforcementGuard::none();
        guard.pin_clock(pinned);
        let held = (Attempt::new(&bob, Door::LdapBind).now, lock_clock());
        drop(guard);
        let now = Timestamp::now();
        let after = (Attempt::new(&bob, Door::LdapBind).now - now).as_millis();
        assert_eq!(
            held,
            (pinned, pinned),
            "pinned: the attempt and the lockout read it"
        );
        assert!(
            (0..1_000).contains(&after),
            "dropped: the time of the moment, {after} ms"
        );
    }

    fn instant(seconds: i64, nanos: u32) -> Timestamp {
        Timestamp::new(seconds, nanos as i32).unwrap()
    }

    #[test]
    #[serial]
    fn test_the_lockouts_clock_is_the_doors_instant_cut_to_whole_microseconds() {
        use lldap_domain_handlers::lockout::{micros_of, time_of_micros};
        let guard = EnforcementGuard::none();
        let rows = [
            (0, 4_102_444_800_000_000),
            (123_456_789, 4_102_444_800_123_456),
            (999_999_999, 4_102_444_800_999_999),
        ];
        for (nanos, micros) in rows {
            guard.pin_clock(instant(4_102_444_800, nanos));
            let at = lock_clock();
            assert_eq!(
                (micros_of(at), time_of_micros(micros)),
                (micros, Some(at)),
                "{nanos} ns"
            );
        }
    }

    #[tokio::test]
    async fn test_a_lock_row_stored_past_the_last_instant_stays_locked_until_the_last_instant() {
        let h = handler().await;
        insert_user_no_password(&h, "g2far").await;
        let far = "INSERT INTO login_lockouts (user_id, fail_count, last_failed) \
                   VALUES ('g2far', 3, '9999-12-31 23:59:59.999999')";
        let far = Statement::from_string(DbBackend::Sqlite, far.to_owned());
        h.sql_pool.execute(far).await.unwrap();
        let row = h.read_lock(&UserId::new("g2far")).await.unwrap().unwrap();
        let policy = LockoutPolicy {
            threshold: 3,
            duration_seconds: 600,
        };
        let now = lock_clock();
        assert_eq!(
            (
                row.last_failed,
                row.locked(policy, now),
                row.lock_end(policy)
            ),
            (Some(Timestamp::MAX), true, Some(Timestamp::MAX)),
            "MySQL's largest DATETIME"
        );
    }

    #[test]
    #[serial]
    fn test_the_guard_turns_the_three_item_flags_off_when_it_drops() {
        use lldap_domain_handlers::enforcement::{ItemFlags, policy_cache};
        let on = ItemFlags {
            login_hours: true,
            networks: true,
            inactivity: true,
        };
        let guard = EnforcementGuard::none();
        policy_cache().set_item_flags(on);
        let held = ItemFlags::held(policy_cache());
        drop(guard);
        assert_eq!(
            (held, ItemFlags::held(policy_cache())),
            (on, ItemFlags::default())
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_the_bind_judges_the_items_and_the_lockout_at_one_instant() {
        let h = handler().await;
        user_in(&h, "q7bind", "q7ou").await;
        threshold(&h, "q7ou", "3").await;
        follow(&h).await;
        lldap_domain_handlers::enforcement::policy_cache().set_lockout_live(false);
        let guard = EnforcementGuard::allowing(&["q7bind"], THRESHOLD);
        let user = UserId::new("q7bind");
        let pinned = Timestamp::from_second(4_102_444_800).unwrap();
        for pin in [None, Some(pinned)] {
            if let Some(at) = pin {
                guard.pin_clock(at);
            }
            assert!(!bind(&h, "q7bind", "Wrong-Pass-1").await, "{pin:?}");
            assert!(bind(&h, "q7bind", RIGHT).await, "{pin:?}");
            let seen = guard.take_seen().into_iter();
            let judged: Vec<_> = seen.map(|seen| seen.now).collect();
            let row = h.read_lock(&user).await.unwrap().unwrap();
            assert_eq!(
                judged,
                vec![row.last_success.unwrap()],
                "{pin:?}: the items are judged at the instant the lockout's success is written"
            );
            if let Some(at) = pin {
                assert_eq!(judged, vec![at], "the pinned instant");
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_bind_counts_refuses_a_locked_user_before_the_password_and_a_success_clears() {
        let log = LogGuard::install_on_this_thread();
        let h = handler().await;
        user_in(&h, "e1bind", "e1bindou").await;
        threshold(&h, "e1bindou", "3").await;
        let meta = RequestMeta::ldap(None, Some("10.71.0.1".parse().unwrap()));
        with_request(meta, async {
            let steps = [
                ("wrong", "nope-1", false, Some(1)),
                ("wrong again", "nope-2", false, Some(2)),
                ("the right password clears", RIGHT, true, Some(0)),
                ("wrong", "nope-3", false, Some(1)),
                ("wrong", "nope-4", false, Some(2)),
                ("the third locks", "nope-5", false, Some(3)),
                ("the right password while locked", RIGHT, false, Some(3)),
                (
                    "a wrong one while locked is not counted",
                    "nope-6",
                    false,
                    Some(3),
                ),
            ];
            for (label, password, ok, count) in steps {
                let got = bind(&h, "e1bind", password).await;
                assert_eq!((got, stored(&h, "e1bind").await), (ok, count), "{label}");
            }
        })
        .await;
        let user = Some("e1bind".to_owned());
        let refused = |detail: &str| (LogKind::Bind, user.clone(), Some(detail.to_owned()));
        let mut expected = vec![refused("invalid credentials"); 2];
        expected.push((LogKind::Bind, user.clone(), None));
        expected.extend(vec![refused("invalid credentials"); 3]);
        expected.push((
            LogKind::AccountLock,
            user.clone(),
            Some("locked: ldap bind".to_owned()),
        ));
        expected.extend(vec![refused(LOCKED_OUT); 2]);
        assert_eq!(rows(&log, &[LogKind::Bind, LogKind::AccountLock]), expected);
    }

    #[tokio::test]
    #[serial]
    async fn test_a_bind_with_no_password_counts_nothing_locked_or_not() {
        let log = LogGuard::install_on_this_thread();
        let h = handler().await;
        user_in(&h, "e3count", "e3countou").await;
        threshold(&h, "e3countou", "2").await;
        let meta = RequestMeta::ldap(None, Some("10.71.3.1".parse().unwrap()));
        let (got, wanted) = with_request(meta, async {
            let before = stored(&h, "e3count").await;
            type Step = (&'static str, &'static str, bool, Option<u32>);
            let steps: [Step; 7] = [
                ("no password", "", false, before),
                ("again", "", false, before),
                ("a code alone", ":123456", false, before),
                (
                    "the password still binds, its count not read",
                    RIGHT,
                    true,
                    None,
                ),
                ("wrong", "nope-1", false, Some(1)),
                ("the second wrong locks", "nope-2", false, Some(2)),
                ("no password while locked", "", false, Some(2)),
            ];
            let (mut got, mut wanted) = (Vec::new(), Vec::new());
            for (label, password, ok, count) in steps {
                let bound = bind(&h, "e3count", password).await;
                let count_now = match ok {
                    true => None,
                    false => stored(&h, "e3count").await,
                };
                got.push((label, bound, count_now));
                wanted.push((label, ok, count));
            }
            (got, wanted)
        })
        .await;
        let user = Some("e3count".to_owned());
        let refused = |detail: &str| (LogKind::Bind, user.clone(), Some(detail.to_owned()));
        let mut expected = vec![refused("no password given"); 3];
        expected.push((LogKind::Bind, user.clone(), None));
        expected.extend(vec![refused("invalid credentials"); 2]);
        expected.push((
            LogKind::AccountLock,
            user.clone(),
            Some("locked: ldap bind".to_owned()),
        ));
        expected.push(refused("no password given"));
        assert_eq!(
            (got, rows(&log, &[LogKind::Bind, LogKind::AccountLock])),
            (wanted, expected),
            "per step: bound, the stored count; then the rows"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_right_password_an_item_refuses_counts_nothing_and_writes_as_a_wrong_one() {
        use lldap_domain_handlers::enforcement::{ItemFlags, policy_cache};
        let guard = EnforcementGuard::default_checks();
        let statements = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut pool = get_initialized_db().await;
        let seen = statements.clone();
        pool.set_metric_callback(move |info| {
            seen.lock().unwrap().push(info.statement.sql.clone());
        });
        let h = own(SqlBackendHandler::new(generate_random_private_key(), pool));
        user_in(&h, "p3item", "p3itemou").await;
        let items = [
            ("login-hours", "mon 08:00-18:00"),
            (THRESHOLD, "5"),
            (DURATION, "0"),
        ];
        policy_on(&h, "p3itemou", &items).await;
        policy_cache().set_item_flags(ItemFlags {
            login_hours: true,
            ..ItemFlags::default()
        });
        guard.pin_clock("2026-11-16T07:00:00Z".parse().unwrap());
        type Step = (&'static str, &'static str, bool, Option<u32>);
        let steps: [Step; 4] = [
            (
                "wrong: the row read, counted, written",
                "nope-1",
                false,
                Some(1),
            ),
            ("wrong again: counted, written", "nope-2", false, Some(2)),
            (
                "right, refused by the hours: nothing counted",
                RIGHT,
                false,
                Some(2),
            ),
            ("right again, refused again", RIGHT, false, Some(2)),
        ];
        let (mut got, mut written) = (Vec::new(), Vec::new());
        for (label, password, _, _) in steps {
            statements.lock().unwrap().clear();
            let bound = bind(&h, "p3item", password).await;
            let sql = std::mem::take(&mut *statements.lock().unwrap());
            let rows = sql.into_iter().filter(|s| s.contains("login_lockouts"));
            written.push(rows.collect::<Vec<_>>());
            got.push((label, password, bound, stored(&h, "p3item").await));
        }
        assert_eq!(got, steps.to_vec(), "per step: bound, the stored count");
        assert!(
            written[1].iter().any(|s| s.starts_with("INSERT")),
            "a wrong password's count is written before it is answered: {:?}",
            written[1]
        );
        assert_eq!(
            (&written[2], &written[3]),
            (&written[1], &written[1]),
            "a refusal after the right password writes the row as it stands, with the statements \
             a wrong password's count takes"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_wrong_binds_at_once_each_count_on_the_current_row() {
        let h = handler().await;
        user_in(&h, "e1many", "e1manyou").await;
        threshold(&h, "e1manyou", "9").await;
        let mut binds = tokio::task::JoinSet::new();
        for i in 0..6 {
            let h = h.clone();
            binds.spawn(async move { bind(&h, "e1many", &format!("nope-{i}")).await });
        }
        while let Some(done) = binds.join_next().await {
            assert!(!done.unwrap());
        }
        h.lockout.drain(&h).await;
        assert_eq!(
            (viewed(&h, "e1many"), stored(&h, "e1many").await),
            (6, Some(6)),
            "six wrong binds at once count six"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_starts_with_no_finish_lock_at_once_and_a_verified_finish_writes_nothing() {
        let h = handler().await;
        for (user, ou) in [
            ("e1web", "e1webou"),
            ("e1one", "e1oneou"),
            ("e1burst", "e1webou"),
        ] {
            user_in(&h, user, ou).await;
        }
        threshold(&h, "e1webou", "3").await;
        threshold(&h, "e1oneou", "1").await;
        for i in 0..2 {
            assert_eq!(
                web(&h, "e1web", &format!("nope-{i}"), None).await,
                Err("client")
            );
        }
        assert_eq!(
            (judged(&h, "e1web"), viewed(&h, "e1web")),
            (2, 0),
            "each start counts at once beside the row, never in it"
        );
        let allowed = web(&h, "e1web", RIGHT, None).await;
        assert!(
            matches!(allowed, Ok(LoginOutcome::Authenticated { .. })),
            "two unfinished starts and the right one: {allowed:?}"
        );
        assert_eq!(
            (judged(&h, "e1web"), stored(&h, "e1web").await),
            (0, None),
            "the right sign-in dropped the two starts before it and wrote nothing"
        );
        for session in 0..3 {
            let allowed = web(&h, "e1one", RIGHT, None).await;
            assert!(
                allowed.is_ok(),
                "threshold 1, session {session}: {allowed:?}"
            );
            assert_eq!(judged(&h, "e1one"), 0, "session {session}");
        }
        h.lockout.write_all_now(&h).await;
        assert!(
            !h.lockout.pending(&UserId::new("e1one")) && stored(&h, "e1one").await.is_none(),
            "a finished start leaves nothing to write"
        );
        for i in 0..3 {
            assert_eq!(
                web(&h, "e1burst", &format!("nope-{i}"), None).await,
                Err("client")
            );
        }
        let burst = UserId::new("e1burst");
        let at_kdc = Attempt::at_kdc(
            &burst,
            Door::KerberosAs,
            None,
            lock_clock().as_second() as u32,
        );
        let kdc = admit_at_kdc_with(h.policy_cache, h.lockout, &at_kdc, &default_item_checks());
        let refused = Err(Refusal {
            item: THRESHOLD,
            door: Door::KerberosAs,
            reason: None,
        });
        assert_eq!(
            (
                kdc,
                bind(&h, "e1burst", RIGHT).await,
                stored(&h, "e1burst").await
            ),
            (refused, false, None),
            "three starts, none written yet: kinit and bind refuse at once"
        );
    }

    const AT: i64 = 1_770_000_015;

    pub(crate) fn pinned() -> (PinnedClock, u64) {
        (pin_clock(AT), AT as u64)
    }

    pub(crate) async fn enroll(handler: &SqlBackendHandler, user: &str, now: u64) -> Vec<u8> {
        let user_id = UserId::new(user);
        let proof = handler.seal_enrollment_proof(&user_id).await.unwrap();
        let start = handler
            .start_totp_enrollment(&user_id, None, proof)
            .await
            .unwrap();
        let seed = lldap_mfa::seed_from_base32(&start.secret_base32).unwrap();
        let code = format_code(totp_code(&seed, now).unwrap());
        handler
            .finish_totp_enrollment(&user_id, &start.state, &code)
            .await
            .unwrap();
        seed
    }

    /// Two codes valid now and not yet used, and one valid at no accepted step.
    pub(crate) fn codes(seed: &[u8], now: u64) -> ([String; 2], String) {
        let at = |t: u64| format_code(totp_code(seed, t).unwrap());
        let valid = [at(now - TOTP_STEP_SECS), at(now), at(now + TOTP_STEP_SECS)];
        let wrong = (0..)
            .map(|c| format!("{c:06}"))
            .find(|c| !valid.contains(c))
            .unwrap();
        ([valid[0].clone(), valid[2].clone()], wrong)
    }

    #[tokio::test]
    #[serial]
    async fn test_a_sessionless_finish_whose_wrong_code_locks_writes_the_lock_row_saying_no_session()
     {
        let (_clock, at) = pinned();
        let log = LogGuard::install_on_this_thread();
        let h = handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        user_in(&h, "e1nosess", "e1nosessou").await;
        threshold(&h, "e1nosessou", "1").await;
        let seed = enroll(&h, "e1nosess", at).await;
        let (_, wrong) = codes(&seed, at);
        rows(&log, &[LogKind::AccountLock]);
        let started = start(&h, "e1nosess", RIGHT).await;
        let mut request = finish_request(started, RIGHT, Some(&wrong)).unwrap();
        request.session = Some(false);
        let answered = without_session(h.login_finish(request)).await;
        let lock = (
            LogKind::AccountLock,
            Some("e1nosess".to_owned()),
            Some("locked: web login; no session".to_owned()),
        );
        assert_eq!(
            (answered.is_err(), rows(&log, &[LogKind::AccountLock])),
            (true, vec![lock]),
            "a sessionless finish whose wrong code reaches the threshold: its lock row says no session"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_enrolled_users_two_steps_net_nothing_and_one_wrong_code_counts_once() {
        let (_clock, at) = pinned();
        let h = handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        for (user, ou) in [("e1two1", "e1t1"), ("e1two2", "e1t2"), ("e1code", "e1c")] {
            user_in(&h, user, ou).await;
        }
        threshold(&h, "e1t1", "1").await;
        threshold(&h, "e1t2", "2").await;
        threshold(&h, "e1c", "9").await;
        let seeds = [
            enroll(&h, "e1two1", at).await,
            enroll(&h, "e1two2", at).await,
        ];
        let step_one = web(&h, "e1two1", RIGHT, None).await;
        assert_eq!(
            (step_one, judged(&h, "e1two1")),
            (Ok(LoginOutcome::TotpRequired), 0)
        );
        let ([code, _], _) = codes(&seeds[0], at);
        let step_two = web(&h, "e1two1", RIGHT, Some(&code)).await;
        assert!(
            step_two.is_ok() && judged(&h, "e1two1") == 0,
            "threshold 1: {step_two:?}"
        );
        assert_eq!(web(&h, "e1two2", "nope", None).await, Err("client"));
        assert_eq!(
            web(&h, "e1two2", RIGHT, None).await,
            Ok(LoginOutcome::TotpRequired)
        );
        let ([code, _], _) = codes(&seeds[1], at);
        let step_two = web(&h, "e1two2", RIGHT, Some(&code)).await;
        assert!(
            step_two.is_ok(),
            "threshold 2, one unfinished start: {step_two:?}"
        );
        assert_eq!(viewed(&h, "e1two2"), 0);

        let seed = enroll(&h, "e1code", at).await;
        let ([first, second], wrong) = codes(&seed, at);
        let with = |code: &str| format!("{RIGHT}:{code}");
        let ldap = || RequestMeta::ldap(None, None);
        let steps: [(&str, &str, Option<u32>); 6] = [
            (
                "web: the right password, a wrong code",
                "web wrong",
                Some(1),
            ),
            (
                "bind: the right password, a wrong code",
                "bind wrong",
                Some(2),
            ),
            ("web: the right password, no code", "web none", Some(2)),
            ("bind: the right password, no code", "bind none", Some(2)),
            ("bind: the right code clears", "bind right", Some(0)),
            (
                "bind: the same code again counts nothing",
                "bind again",
                Some(0),
            ),
        ];
        for (label, case, count) in steps {
            match case {
                "web wrong" => assert!(web(&h, "e1code", RIGHT, Some(&wrong)).await.is_err()),
                "web none" => assert!(web(&h, "e1code", RIGHT, None).await.is_ok()),
                "bind wrong" => {
                    assert!(!with_request(ldap(), bind(&h, "e1code", &with(&wrong))).await)
                }
                "bind none" => assert!(!with_request(ldap(), bind(&h, "e1code", RIGHT)).await),
                "bind right" => {
                    assert!(with_request(ldap(), bind(&h, "e1code", &with(&first))).await)
                }
                _ => assert!(!with_request(ldap(), bind(&h, "e1code", &with(&first))).await),
            }
            assert_eq!(stored(&h, "e1code").await, count, "{label}");
        }
        assert!(with_request(ldap(), bind(&h, "e1code", &with(&second))).await);
    }

    #[tokio::test]
    #[serial]
    async fn test_a_completed_sign_in_drops_the_wrong_starts_before_it_and_code_required_does_not()
    {
        let (_clock, at) = pinned();
        let h = handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        user_in(&h, "e1clean", "e1cleanou").await;
        user_in(&h, "e1coded", "e1cleanou").await;
        threshold(&h, "e1cleanou", "9").await;
        enroll(&h, "e1coded", at).await;
        for user in ["e1clean", "e1coded"] {
            for i in 0..2 {
                assert_eq!(
                    web(&h, user, &format!("nope-{i}"), None).await,
                    Err("client")
                );
            }
        }
        assert!(matches!(
            web(&h, "e1clean", RIGHT, None).await,
            Ok(LoginOutcome::Authenticated { .. })
        ));
        assert_eq!(
            web(&h, "e1coded", RIGHT, None).await,
            Ok(LoginOutcome::TotpRequired)
        );
        h.lockout.write_all_now(&h).await;
        assert_eq!(
            (
                stored(&h, "e1clean").await.unwrap_or(0),
                stored(&h, "e1coded").await
            ),
            (0, Some(2)),
            "once the starts expire: none came back after the right sign-in; a finish that \
             stops at code required dropped nothing, so both wrong starts count"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_locked_account_hammered_at_the_bind_is_read_at_most_once_a_second() {
        let statements = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut pool = get_initialized_db().await;
        let seen = statements.clone();
        pool.set_metric_callback(move |info| {
            seen.lock().unwrap().push(info.statement.sql.clone());
        });
        let h = own(SqlBackendHandler::new(generate_random_private_key(), pool));
        user_in(&h, "e1hammer", "e1hammerou").await;
        threshold(&h, "e1hammerou", "1").await;
        assert!(!bind(&h, "e1hammer", "nope").await);
        h.lockout.write_all_now(&h).await;
        statements.lock().unwrap().clear();
        for i in 0..10 {
            let password = if i % 2 == 0 { RIGHT } else { "nope" };
            assert!(!bind(&h, "e1hammer", password).await, "try {i}");
        }
        let reads = statements
            .lock()
            .unwrap()
            .iter()
            .filter(|sql| sql.contains("login_lockouts") && sql.starts_with("SELECT"))
            .count();
        assert!(
            (1..=2).contains(&reads),
            "ten refused binds within a second confirm the lock at most once a second: {reads}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_ticket_on_the_password_alone_clears_nothing_for_a_user_with_a_second_factor() {
        let (_clock, at) = pinned();
        let h = handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        user_in(&h, "e1factor", "e1factorou").await;
        threshold(&h, "e1factorou", "9").await;
        let user = UserId::new("e1factor");
        let ticket = || {
            let lock = h.lockout.kdc_state(h.policy_cache, &user).unwrap();
            h.lockout.ticket_issued(h.policy_cache, &lock, lock_clock())
        };
        for i in 0..2 {
            assert!(!bind(&h, "e1factor", &format!("nope-{i}")).await);
        }
        enroll(&h, "e1factor", at).await;
        assert_eq!(
            (ticket(), viewed(&h, "e1factor")),
            (Step::default(), 2),
            "enrolled: a ticket on the password alone clears nothing"
        );
        h.reset_user_mfa(&user, MfaResetReason::Administrative)
            .await
            .unwrap();
        let cleared = ticket();
        assert_eq!(
            (cleared == Step::default(), viewed(&h, "e1factor")),
            (false, 0),
            "the factor reset: the ticket clears as any sign-in"
        );
        assert!(!bind(&h, "e1factor", "nope-2").await);
        h.policy_cache.remove_user(&user);
        assert_eq!(
            (ticket(), viewed(&h, "e1factor")),
            (Step::default(), 1),
            "nothing known of the user's factors: nothing cleared"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_lock_that_web_starts_reach_is_logged_from_the_starts_peer() {
        let log = LogGuard::install_on_this_thread();
        for sessionless in [false, true] {
            let h = handler().await;
            user_in(&h, "e1peer", "e1peerou").await;
            threshold(&h, "e1peerou", "1").await;
            let started = RequestMeta::http(Some("10.71.0.9".parse().unwrap()), None);
            let wrong = web(&h, "e1peer", "nope", None);
            assert_eq!(with_request(started, wrong).await, Err("client"));
            let elsewhere = RequestMeta::ldap(None, Some("10.71.0.10".parse().unwrap()));
            let fold = h.lockout.write_all_now(&h);
            match sessionless {
                true => with_request(elsewhere, without_session(fold)).await,
                false => with_request(elsewhere, fold).await,
            }
            let locks: Vec<_> = log
                .recorder()
                .take_events()
                .into_iter()
                .filter(|event| event.kind == LogKind::AccountLock)
                .map(|event| (event.protocol, event.peer, event.detail))
                .collect();
            let start = (
                Protocol::Http,
                Some("10.71.0.9".to_owned()),
                Some(lock_detail(Door::WebLogin)),
            );
            assert_eq!(
                locks,
                vec![start],
                "flushed by a sessionless finish: {sessionless}; the row is the start's alone"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_name_made_again_on_another_server_inherits_nothing_there() {
        let pool = get_initialized_db().await;
        let (a, b) = servers(&pool);
        user_in(&a, "e1again", "e1againou").await;
        threshold(&a, "e1againou", "5").await;
        follow(&b).await;
        for i in 0..4 {
            assert!(!bind(&a, "e1again", &format!("nope-{i}")).await);
        }
        b.lockout.refresh(&b).await.unwrap();
        assert_eq!(viewed(&b, "e1again"), 4, "the second server reads the row");
        a.delete_user(&UserId::new("e1again")).await.unwrap();
        user_in(&a, "e1again", "e1againou").await;
        fill_policy_cache(&b, b.policy_cache).await.unwrap();
        assert!(!bind(&b, "e1again", "nope-4").await);
        assert_eq!(
            (stored(&a, "e1again").await, viewed(&b, "e1again")),
            (Some(1), 1),
            "the new account's first typo counts 1 there, not 5"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_ticket_clears_only_where_the_bind_would_ask_no_code() {
        let (_clock, at) = pinned();
        for (label, policy, exempt, count) in [
            (
                "enrolled, the second factor on",
                MfaPolicy::Enrolled,
                false,
                1,
            ),
            ("enrolled and exempt", MfaPolicy::Enrolled, true, 0),
            (
                "enrolled, the second factor off",
                MfaPolicy::Disabled,
                false,
                0,
            ),
        ] {
            let h = handler().await.with_mfa_policy(MfaPolicy::Enrolled);
            user_in(&h, "e1exempt", "e1exemptou").await;
            threshold(&h, "e1exemptou", "9").await;
            enroll(&h, "e1exempt", at).await;
            if exempt {
                let group = insert_group(&h, MFA_DISABLED_GROUP).await;
                insert_membership(&h, group, "e1exempt").await;
            }
            let h = h.with_mfa_policy(policy);
            assert!(!bind(&h, "e1exempt", "nope").await);
            let user = UserId::new("e1exempt");
            let lock = h.lockout.kdc_state(h.policy_cache, &user).unwrap();
            let _ = h.lockout.ticket_issued(h.policy_cache, &lock, lock_clock());
            assert_eq!(viewed(&h, "e1exempt"), count, "{label}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_ticket_clears_where_the_bind_asks_no_code_the_ous_item_counted() {
        let (_clock, at) = pinned();
        let rows = [
            ("an OU's always, enrolled", None, "always", true, 1),
            ("an OU's always, no factor", None, "always", false, 0),
            ("an OU's enabled, enrolled", None, "enabled", true, 1),
            (
                "an OU's enabled, an explicit off",
                Some(MfaPolicy::Disabled),
                "enabled",
                true,
                0,
            ),
            (
                "an OU's off, an explicit enabled",
                Some(MfaPolicy::Enrolled),
                "off",
                true,
                1,
            ),
        ];
        for (label, server, item, enrolled, count) in rows {
            let h = handler().await;
            user_in(&h, "e2ticket", "e2ticketou").await;
            let items = [(THRESHOLD, "9"), (DURATION, "0"), ("enable-mfa", item)];
            policy_on(&h, "e2ticketou", &items).await;
            if enrolled {
                enroll(&h, "e2ticket", at).await;
            }
            let h = h.with_mfa_setting(server);
            assert!(!bind(&h, "e2ticket", "nope").await, "{label}");
            let user = UserId::new("e2ticket");
            let asks = h.mfa_requirement(&user).await.unwrap() == MfaRequirement::Totp;
            let lock = h.lockout.kdc_state(h.policy_cache, &user).unwrap();
            let _ = h.lockout.ticket_issued(h.policy_cache, &lock, lock_clock());
            assert_eq!(
                (viewed(&h, "e2ticket"), asks),
                (count, count == 1),
                "{label}: the ticket clears only where the bind asks no code"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_code_refused_as_unreadable_writes_one_row_and_counts_nothing() {
        let (_clock, at) = pinned();
        let log = LogGuard::install_on_this_thread();
        let h = handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        user_in(&h, "e1bgone", "e1bgoneou").await;
        threshold(&h, "e1bgoneou", "9").await;
        let seed = enroll(&h, "e1bgone", at).await;
        let ([code, _], _) = codes(&seed, at);
        let backend = h.sql_pool.get_database_backend();
        let drop = Statement::from_string(backend, "DROP TABLE totp_steps".to_owned());
        h.sql_pool.execute(drop).await.unwrap();
        let _ = rows(&log, &[LogKind::Bind]);
        let refused = bind_as(&h, "e1bgone", &format!("{RIGHT}:{code}")).await;
        let detail = Some("totp: unreadable".to_owned());
        assert_eq!(
            (
                refused.is_err_and(|e| e.to_string().contains("TOTP state unreadable")),
                stored(&h, "e1bgone").await,
                viewed(&h, "e1bgone"),
                rows(&log, &[LogKind::Bind])
            ),
            (
                true,
                None,
                0,
                vec![(LogKind::Bind, Some("e1bgone".to_owned()), detail)]
            ),
            "one row with its own detail, and nothing counted"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_code_refused_for_too_many_attempts_writes_one_row_and_counts_nothing() {
        let (_clock, at) = pinned();
        let log = LogGuard::install_on_this_thread();
        let h = handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        user_in(&h, "e1bmany", "e1bmanyou").await;
        threshold(&h, "e1bmanyou", "9").await;
        let seed = enroll(&h, "e1bmany", at).await;
        let ([_, right], wrong) = codes(&seed, at);
        let wrong = format!("{RIGHT}:{wrong}");
        for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
            assert!(!bind(&h, "e1bmany", &wrong).await);
        }
        let _ = rows(&log, &[LogKind::Bind]);
        let refused = bind_as(&h, "e1bmany", &format!("{RIGHT}:{right}")).await;
        let detail = Some("totp attempts exceeded".to_owned());
        assert_eq!(
            (
                refused.is_err_and(|e| e.to_string().contains(TOTP_TOO_MANY_ATTEMPTS)),
                stored(&h, "e1bmany").await,
                rows(&log, &[LogKind::Bind])
            ),
            (
                true,
                Some(5),
                vec![(LogKind::Bind, Some("e1bmany".to_owned()), detail)]
            ),
            "the five wrong codes count; the sixth try writes its one row and counts nothing"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_locked_users_right_and_wrong_passwords_get_the_same_answer_byte_for_byte() {
        let h = handler().await;
        user_in(&h, "e1same", "e1sameou").await;
        user_in(&h, "e1open", "e1openou").await;
        let id = threshold(&h, "e1sameou", "5").await;
        threshold(&h, "e1openou", "5").await;
        for i in 0..2 {
            assert!(!bind(&h, "e1same", &format!("nope-{i}")).await);
        }
        let right = finish_request(start(&h, "e1same", RIGHT).await, RIGHT, None).unwrap();
        let mut forged = finish_request(start(&h, "e1same", RIGHT).await, RIGHT, None).unwrap();
        forged.credential_finalization = right.credential_finalization.clone();
        let mut unlocked = finish_request(start(&h, "e1open", RIGHT).await, RIGHT, None).unwrap();
        unlocked.credential_finalization = right.credential_finalization.clone();
        let request = UpdatePolicyRequest {
            id,
            name: None,
            description: None,
            items: Some([(THRESHOLD.to_owned(), "2".to_owned())].into()),
        };
        h.update_policy(request).await.unwrap();
        let text = |e: DomainError| e.to_string();
        let answers = (
            h.login_finish(right).await.map_err(text),
            h.login_finish(forged).await.map_err(text),
            h.login_finish(unlocked).await.map_err(text),
        );
        let failed =
            Err(DomainError::from(opaque::AuthenticationError::failed_proof()).to_string());
        assert_eq!(
            answers,
            (failed.clone(), failed.clone(), failed),
            "web finish: locked with the right proof, locked with a forged one, and an unlocked \
             user's forged one"
        );
        let bind_text = async |password: &str| bind_as(&h, "e1same", password).await.map_err(text);
        assert_eq!(
            (bind_text(RIGHT).await, bind_text("nope-9").await),
            (
                Err(invalid_credentials(&UserId::new("e1same")).to_string()),
                Err(invalid_credentials(&UserId::new("e1same")).to_string())
            ),
            "bind and simple login: the right and a wrong password"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_locked_users_start_answers_as_an_unknown_name_and_no_name_gets_a_row() {
        let log = LogGuard::install_on_this_thread();
        let h = handler().await;
        user_in(&h, "e1shape", "e1shapeou").await;
        user_in(&h, "e1late", "e1lateou").await;
        insert_user_no_password(&h, "e1nopass").await;
        threshold(&h, "e1shapeou", "1").await;
        let late = threshold(&h, "e1lateou", "3").await;
        let meta = RequestMeta::http(Some("10.71.0.5".parse().unwrap()), None);
        with_request(meta, async {
            assert!(!bind(&h, "e1shape", "nope").await);
            rows(&log, &[LogKind::Bind, LogKind::AccountLock]);
            let locked = web(&h, "e1shape", RIGHT, None).await;
            let unknown = web(&h, "e1nobody", RIGHT, None).await;
            assert_eq!(
                (locked, unknown),
                (Err("client"), Err("client")),
                "a 200 with a credential response the client cannot finish, both"
            );
            assert_eq!(judged(&h, "e1shape"), 1, "not counted while locked");
            assert_eq!(
                rows(&log, &[LogKind::Login, LogKind::AccountLock]),
                vec![(
                    LogKind::Login,
                    Some("e1shape".to_owned()),
                    Some(LOCKED_OUT.to_owned())
                )]
            );
            for _ in 0..3 {
                assert!(!bind(&h, "e1nobody", "nope").await);
                assert!(!bind(&h, "e1nopass", "nope").await);
                assert_eq!(web(&h, "e1nobody", "nope", None).await, Err("client"));
            }
            for user in ["e1nobody", "e1nopass"] {
                assert_eq!(
                    (stored(&h, user).await, judged(&h, user)),
                    (None, 0),
                    "{user}"
                );
            }
            assert!(!h.lockout.pending(&UserId::new("e1nobody")));

            assert!(!bind(&h, "e1late", "nope-1").await);
            assert!(!bind(&h, "e1late", "nope-2").await);
            let started = start(&h, "e1late", RIGHT).await;
            let request = UpdatePolicyRequest {
                id: late,
                name: None,
                description: None,
                items: Some([(THRESHOLD.to_owned(), "2".to_owned())].into()),
            };
            h.update_policy(request).await.unwrap();
            let finish = finish_request(started, RIGHT, None).unwrap();
            assert!(
                h.login_finish(finish).await.is_err(),
                "judged once its own start is removed"
            );
            assert_eq!((viewed(&h, "e1late"), judged(&h, "e1late")), (2, 2));
        })
        .await;
        let refused = (
            LogKind::Login,
            Some("e1late".to_owned()),
            Some(LOCKED_OUT.to_owned()),
        );
        assert_eq!(
            rows(&log, &[LogKind::Login, LogKind::AccountLock]),
            vec![refused],
            "a lock no counted failure reached logs no account_lock; the refusal has its row"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_web_start_is_as_long_for_a_live_an_unknown_and_a_locked_name() {
        let h = handler().await;
        user_in(&h, "e1len1", "e1lenou").await;
        user_in(&h, "e1len2", "e1lenou").await;
        threshold(&h, "e1lenou", "1").await;
        assert!(!bind(&h, "e1len2", "nope").await);
        let length = async |user: &str| start(&h, user, RIGHT).await.1.server_data.len();
        let live = length("e1len1").await;
        assert_eq!(
            h.lockout.overlays(&UserId::new("e1len1")),
            1,
            "the live start counts"
        );
        assert_eq!(
            [length("e1len0").await, length("e1len2").await],
            [live, live],
            "an unknown name and a locked one answer as long as a live one"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_name_created_again_never_inherits_the_old_accounts_state() {
        let h = handler().await;
        user_in(&h, "e1reborn", "e1rebornou").await;
        threshold(&h, "e1rebornou", "1").await;
        assert!(!bind(&h, "e1reborn", "nope").await);
        let user = UserId::new("e1reborn");
        assert!(h.lockout.row(&user).is_some());
        h.delete_user(&user).await.unwrap();
        assert_eq!(
            (h.lockout.row(&user), h.lockout.pending(&user)),
            (None, false),
            "forgotten in the delete's own path"
        );
        user_in(&h, "e1reborn", "e1rebornou").await;
        let now = lock_clock().as_second() as u32;
        let at_kdc = Attempt::at_kdc(&user, Door::KerberosAs, None, now);
        let checks = default_item_checks();
        assert_eq!(
            (
                admit_at_kdc_with(h.policy_cache, h.lockout, &at_kdc, &checks),
                bind(&h, "e1reborn", RIGHT).await
            ),
            (Ok(()), true),
            "the new account's kinit and bind are answered"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_failure_in_flight_for_a_user_deleted_meanwhile_creates_nothing() {
        let h = handler().await;
        user_in(&h, "e1flight", "e1flightou").await;
        threshold(&h, "e1flightou", "3").await;
        let user = UserId::new("e1flight");
        let lock = h.lock_state(&user).await.unwrap();
        h.delete_user(&user).await.unwrap();
        h.count_failure(lock.as_ref(), Door::LdapBind, lock_clock())
            .await;
        assert_eq!(
            (
                h.lockout.row(&user),
                h.lockout.pending(&user),
                stored(&h, "e1flight").await
            ),
            (None, false, None)
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_until_the_policies_are_read_every_door_refuses() {
        let log = LogGuard::install_on_this_thread();
        let h = handler().await;
        user_in(&h, "e1unread", "e1unreadou").await;
        h.policy_cache.set_lockout_unknown();
        assert!(!bind(&h, "e1unread", RIGHT).await);
        assert_eq!(
            rows(&log, &[LogKind::Bind]),
            vec![(
                LogKind::Bind,
                Some("e1unread".to_owned()),
                Some("policy: unreadable".to_owned())
            )]
        );
        follow(&h).await;
        assert!(
            !h.policy_cache.lockout_unknown() && bind(&h, "e1unread", RIGHT).await,
            "the follow reads it: no threshold anywhere, so counting is off and the door serves"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_once_counting_is_on_every_user_counts_and_a_later_threshold_applies_at_once() {
        let h = handler().await;
        user_in(&h, "e1queued", "e1queuedou").await;
        user_in(&h, "e1mover", "e1plainou").await;
        threshold(&h, "e1elsewhere", "3").await;
        for i in 0..3 {
            assert!(!bind(&h, "e1queued", &format!("nope-{i}")).await);
            assert!(!bind(&h, "e1mover", &format!("nope-{i}")).await);
        }
        assert_eq!(
            (stored(&h, "e1queued").await, viewed(&h, "e1queued")),
            (None, 3),
            "counted in memory with no threshold of its own, the write owed"
        );
        threshold(&h, "e1queuedou", "3").await;
        assert!(
            !bind(&h, "e1queued", RIGHT).await,
            "a second OU's threshold applies at once to the failures already counted"
        );
        let moved = UpdateUserRequest {
            user_id: UserId::new("e1mover"),
            insert_attributes: vec![Attribute {
                name: "ou".into(),
                value: "e1queuedou".to_owned().into(),
            }],
            ..Default::default()
        };
        h.update_user(moved).await.unwrap();
        assert!(
            !bind(&h, "e1mover", RIGHT).await,
            "and so does a move under one"
        );
        assert_eq!(
            h.lockout.drain(&h).await,
            2,
            "one entry per user, the latest row"
        );
        assert_eq!(
            (stored(&h, "e1queued").await, stored(&h, "e1mover").await),
            (Some(3), Some(3)),
            "a second threshold does not start counting again"
        );
    }

    async fn set_threshold(handler: &SqlBackendHandler, id: PolicyId, value: &str) {
        let request = UpdatePolicyRequest {
            id,
            name: None,
            description: None,
            items: Some(
                [
                    (THRESHOLD.to_owned(), value.to_owned()),
                    (DURATION.to_owned(), "0".to_owned()),
                ]
                .into(),
            ),
        };
        handler.update_policy(request).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_counting_starts_from_zero_when_the_first_threshold_takes_effect() {
        let h = handler().await;
        user_in(&h, "e1zero", "e1zeroou").await;
        let id = threshold(&h, "e1zeroou", "5").await;
        let first: u64 = h.read_period().await.unwrap().parse().unwrap();
        for i in 0..4 {
            assert!(!bind(&h, "e1zero", &format!("nope-{i}")).await);
        }
        assert_eq!(stored(&h, "e1zero").await, Some(4));
        set_threshold(&h, id, "0").await;
        assert!(
            !h.policy_cache.lockout_live(),
            "no threshold anywhere: counting is off"
        );
        assert!(bind(&h, "e1zero", RIGHT).await, "a right sign-in");
        assert_eq!(
            stored(&h, "e1zero").await,
            Some(4),
            "clears nothing while off"
        );
        set_threshold(&h, id, "5").await;
        assert_eq!(
            (
                stored(&h, "e1zero").await,
                viewed(&h, "e1zero"),
                h.read_period().await.unwrap(),
                h.lockout.period()
            ),
            (Some(0), 0, (first + 1).to_string(), (first + 1).to_string()),
            "raised from 0 on a linked policy: zeroed and a new period in the change's transaction"
        );
        assert!(!bind(&h, "e1zero", "nope-4").await);
        assert_eq!(
            stored(&h, "e1zero").await,
            Some(1),
            "one wrong password reads 1"
        );
        assert!(bind(&h, "e1zero", RIGHT).await, "and does not lock");

        let user = UserId::new("e1zero");
        h.clear_ou_policy("e1zeroou").await.unwrap();
        let kept = LockRow {
            fail_count: 5,
            last_failed: Some(time(9, 0)),
            last_success: Some(time(1, 0)),
            last_admin_unlock: Some(time(2, 0)),
            lock_logged: Some(time(8, 0)),
        };
        h.write_locks(&h.lockout.period(), &[write(&user, kept)])
            .await
            .unwrap();
        h.set_ou_policy("e1zeroou", id).await.unwrap();
        assert_eq!(
            h.read_lock(&user).await.unwrap(),
            Some(LockRow {
                fail_count: 0,
                lock_logged: None,
                ..kept
            }),
            "linked again: every counting field is zeroed, the logged lock too; the unlock stays"
        );
        for i in 5..10 {
            assert!(!bind(&h, "e1zero", &format!("nope-{i}")).await);
        }
        let relocked = h.read_lock(&user).await.unwrap().unwrap();
        assert_eq!(
            (relocked.fail_count, relocked.lock_logged.is_some()),
            (5, true),
            "locked again in the new period, and that lock is logged"
        );
        threshold(&h, "e1secondou", "5").await;
        assert_eq!(
            stored(&h, "e1zero").await,
            Some(5),
            "a second threshold zeroes nothing"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_server_that_missed_an_off_and_on_turn_writes_no_old_count_back() {
        let pool = get_initialized_db().await;
        let (a, b) = servers(&pool);
        user_in(&a, "e1old", "e1oldou").await;
        let id = threshold(&a, "e1lockedou", "3").await;
        follow(&b).await;
        for i in 0..3 {
            assert!(!bind(&b, "e1old", &format!("nope-{i}")).await);
        }
        assert!(b.lockout.pending(&UserId::new("e1old")), "owed on b");
        set_threshold(&a, id, "0").await;
        set_threshold(&a, id, "3").await;
        assert_eq!(b.lockout.drain(&b).await, 1);
        assert_eq!(
            stored(&b, "e1old").await,
            None,
            "b's count from the period before is not written back"
        );
        follow(&b).await;
        assert_eq!(
            (b.lockout.period(), viewed(&b, "e1old")),
            (a.lockout.period(), 0),
            "b's next follow sees the period moved, forgets and reads again"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_bound_write_gives_way_to_a_held_connection_and_is_retried() {
        let h = handler().await;
        user_in(&h, "e1busy", "e1busyou").await;
        threshold(&h, "e1busyou", "5").await;
        let user = UserId::new("e1busy");
        h.lock_state(&user).await.unwrap();
        let held = h.sql_pool.begin().await.unwrap();
        let started = Instant::now();
        let answered = with_request(RequestMeta::ldap(None, None), async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let lock = h.lock_state(&user).await.unwrap();
                h.count_failure(lock.as_ref(), Door::LdapBind, lock_clock())
                    .await;
            })
            .await
        })
        .await;
        let took = started.elapsed();
        held.rollback().await.unwrap();
        assert!(
            answered.is_ok() && took < Duration::from_millis(400),
            "{took:?}"
        );
        assert!(h.lockout.pending(&user), "owed, not dropped");
        assert_eq!(h.lockout.drain(&h).await, 1);
        assert_eq!(stored(&h, "e1busy").await, Some(1));
    }

    #[tokio::test]
    #[serial]
    async fn test_no_threshold_anywhere_costs_todays_statements_and_a_threshold_one_read() {
        let statements = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut pool = get_initialized_db().await;
        let seen = statements.clone();
        pool.set_metric_callback(move |info| {
            seen.lock().unwrap().push(info.statement.sql.clone());
        });
        let h = own(SqlBackendHandler::new(generate_random_private_key(), pool));
        user_in(&h, "e1quiet", "e1quietou").await;
        let user = UserId::new("e1quiet");
        let run = async |kind: &str| -> Vec<String> {
            statements.lock().unwrap().clear();
            match kind {
                "bind" => assert!(bind(&h, "e1quiet", RIGHT).await),
                "refresh" => {
                    let attempt = Attempt::new(&user, Door::Refresh);
                    assert!(admit(&h, &attempt).await.is_ok());
                }
                "token" => {
                    let attempt = Attempt::new(&user, Door::TokenUse);
                    assert!(admit(&h, &attempt).await.is_ok());
                }
                _ => assert!(web(&h, "e1quiet", RIGHT, None).await.is_ok()),
            }
            std::mem::take(&mut *statements.lock().unwrap())
        };
        let ours = |sql: &[String]| -> Vec<String> {
            let lockouts = sql.iter().filter(|s| s.contains("login_lockouts"));
            lockouts.cloned().collect()
        };
        for kind in ["bind", "web", "refresh", "token"] {
            let today = {
                let _none = EnforcementGuard::none();
                run(kind).await
            };
            let registered = run(kind).await;
            assert_eq!(
                registered, today,
                "{kind}: no threshold anywhere, no extra statement"
            );
        }
        assert!(!h.policy_cache.lockout_live() && h.lockout.is_empty());
        let id = threshold(&h, "e1quietou", "3").await;
        assert!(
            h.policy_cache.lockout_live(),
            "the first threshold turns the lockout on"
        );
        for (kind, reads) in [("bind", 1), ("web", 0)] {
            let today = {
                let _none = EnforcementGuard::none();
                run(kind).await
            };
            let with = run(kind).await;
            let others: Vec<String> = with
                .iter()
                .filter(|s| !s.contains("login_lockouts"))
                .cloned()
                .collect();
            let lockouts = ours(&with);
            assert_eq!(others, today, "{kind}");
            assert!(
                lockouts.len() == reads && lockouts.iter().all(|s| s.starts_with("SELECT")),
                "{kind}: the row is read once, then held; nothing written: {lockouts:?}"
            );
        }
        h.lockout.write_all_now(&h).await;
        assert!(
            !h.lockout.pending(&user) && stored(&h, "e1quiet").await.is_none(),
            "sign-ins at 0 leave nothing owed and write nothing"
        );
        h.delete_policy(id).await.unwrap();
        assert!(
            !h.policy_cache.lockout_live() && h.lockout.is_empty(),
            "and the last one removed turns it off and forgets"
        );
    }
}
