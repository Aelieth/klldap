use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_policy_handler::policy_levels_on;
use async_trait::async_trait;
use lldap_domain::types::{User, UserId, user_ou};
use lldap_domain_handlers::enforcement::POLICY_UNANSWERED;
use lldap_domain_handlers::policies::{POLICY_READ_WAIT, PolicyLevel, canonical_ou_key};
use lldap_domain_model::error::{DomainError, Result};
use sea_orm::sea_query::Values;
use sea_orm::sqlx::mysql::MySqlDatabaseError;
use sea_orm::sqlx::{self, MySql, pool::PoolConnection};
use sea_orm::{
    ConnectionTrait, DbBackend, DbErr, ExecResult, QueryResult, RuntimeErr, Statement,
    TransactionTrait,
};
use sea_query_binder::SqlxValues;
use std::time::Duration;
use tokio::sync::Mutex;

/// The database ends a read waiting on a lock before the client's timer, unless the read waited
/// for its connection first.
pub(crate) const SERVER_BOUND: Duration =
    POLICY_READ_WAIT.saturating_sub(Duration::from_millis(500));
const READS_ONLY: &str = "a bounded read's session runs reads only";

type Entry = (User, Vec<PolicyLevel>);
type Found = (Option<User>, Vec<PolicyLevel>);

/// What one bounded read reads: a user and its OU's levels, or one OU's levels.
#[derive(Clone, Copy)]
enum Read<'a> {
    User(&'a UserId),
    Ou(&'a str),
}

async fn read_on(db: &impl ConnectionTrait, read: Read<'_>) -> Result<Found> {
    let (details, ou_key) = match read {
        Read::User(user) => {
            let details = SqlBackendHandler::user_details_on(db, user).await?;
            let ou_key = canonical_ou_key(&user_ou(&details.attributes));
            (Some(details), ou_key)
        }
        Read::Ou(ou_key) => (None, ou_key.to_owned()),
    };
    let levels = policy_levels_on(db, &ou_key).await?;
    Ok((details, levels))
}

/// PostgreSQL's lock and statement timeouts; MySQL's lock wait and statement time; MariaDB's.
fn bound_reached(code: Option<&str>, number: Option<u16>) -> bool {
    matches!(code, Some("55P03" | "57014")) || matches!(number, Some(1205 | 3024 | 1969))
}

fn bound_reached_by(err: &DbErr) -> bool {
    let db = match err {
        DbErr::Query(RuntimeErr::SqlxError(sqlx::Error::Database(db)))
        | DbErr::Exec(RuntimeErr::SqlxError(sqlx::Error::Database(db))) => db,
        _ => return false,
    };
    let number = db.try_downcast_ref::<MySqlDatabaseError>();
    bound_reached(db.code().as_deref(), number.map(MySqlDatabaseError::number))
}

impl SqlBackendHandler {
    pub(crate) async fn bounded_entry(&self, user: &UserId) -> Result<Entry> {
        match self.bounded(Read::User(user)).await? {
            (Some(details), levels) => Ok((details, levels)),
            (None, _) => Err(DomainError::EntityNotFound(user.to_string())),
        }
    }

    pub(crate) async fn bounded_levels(&self, ou_key: &str) -> Result<Vec<PolicyLevel>> {
        Ok(self.bounded(Read::Ou(ou_key)).await?.1)
    }

    async fn bounded(&self, read: Read<'_>) -> Result<Found> {
        let answer = match self.sql_pool.get_database_backend() {
            DbBackend::MySql => self.mysql_read(read).await,
            _ => self.transaction_read(read).await,
        };
        answer.map_err(|e| match e {
            DomainError::DatabaseError(db) if bound_reached_by(&db) => {
                DomainError::InternalError(POLICY_UNANSWERED.to_owned())
            }
            e => e,
        })
    }

    async fn transaction_read(&self, read: Read<'_>) -> Result<Found> {
        let txn = self.sql_pool.begin().await?;
        if txn.get_database_backend() == DbBackend::Postgres {
            for bound in ["lock_timeout", "statement_timeout"] {
                let set = format!("SET LOCAL {bound} = {}", SERVER_BOUND.as_millis());
                txn.execute_unprepared(&set).await?;
            }
        }
        let answer = read_on(&txn, read).await;
        let _ = txn.rollback().await;
        answer
    }

    async fn mysql_read(&self, read: Read<'_>) -> Result<Found> {
        let pool = self.sql_pool.get_mysql_connection_pool();
        let conn = pool.acquire().await.map_err(conn_failed)?;
        let mut session = BoundSession {
            conn: Mutex::new(conn),
            put_back: false,
        };
        let version = Statement::from_string(DbBackend::MySql, "SELECT VERSION()");
        let version: String = match session.query_one(version).await? {
            Some(row) => row.try_get_by_index(0)?,
            None => String::new(),
        };
        let (statement, limit) = statement_bound(&version);
        let bound = format!(
            "SET @klldap_lock_wait = @@SESSION.lock_wait_timeout, \
             @klldap_statement_wait = @@SESSION.{statement}, \
             SESSION lock_wait_timeout = {}, SESSION {statement} = {limit}",
            SERVER_BOUND.as_secs().max(1)
        );
        session.execute_unprepared(&bound).await?;
        let answer = read_on(&session, read).await;
        let restore = format!(
            "SET SESSION lock_wait_timeout = @klldap_lock_wait, \
             SESSION {statement} = @klldap_statement_wait"
        );
        session.execute_unprepared(&restore).await?;
        session.put_back = true;
        answer
    }
}

/// MariaDB bounds a statement in seconds, MySQL a SELECT in milliseconds.
fn statement_bound(version: &str) -> (&'static str, String) {
    match version.to_ascii_lowercase().contains("mariadb") {
        true => ("max_statement_time", SERVER_BOUND.as_secs_f64().to_string()),
        false => ("max_execution_time", SERVER_BOUND.as_millis().to_string()),
    }
}

/// MySQL bounds a session, not a transaction: a connection whose bounds are not put back is closed.
struct BoundSession {
    conn: Mutex<PoolConnection<MySql>>,
    put_back: bool,
}

impl Drop for BoundSession {
    fn drop(&mut self) {
        if !self.put_back {
            self.conn.get_mut().close_on_drop();
        }
    }
}

fn conn_failed(err: sqlx::Error) -> DbErr {
    DbErr::Conn(RuntimeErr::SqlxError(err))
}

fn exec_failed(err: sqlx::Error) -> DbErr {
    DbErr::Exec(RuntimeErr::SqlxError(err))
}

fn query_failed(err: sqlx::Error) -> DbErr {
    DbErr::Query(RuntimeErr::SqlxError(err))
}

fn bound_values(values: Option<Values>) -> SqlxValues {
    SqlxValues(values.unwrap_or(Values(Vec::new())))
}

#[async_trait]
impl ConnectionTrait for BoundSession {
    fn get_database_backend(&self) -> DbBackend {
        DbBackend::MySql
    }

    async fn execute(&self, _: Statement) -> std::result::Result<ExecResult, DbErr> {
        Err(DbErr::Custom(READS_ONLY.to_owned()))
    }

    async fn execute_unprepared(&self, sql: &str) -> std::result::Result<ExecResult, DbErr> {
        let mut conn = self.conn.lock().await;
        let done = sqlx::Executor::execute(&mut **conn, sql).await;
        done.map(ExecResult::from).map_err(exec_failed)
    }

    async fn query_one(&self, stmt: Statement) -> std::result::Result<Option<QueryResult>, DbErr> {
        let values = bound_values(stmt.values);
        let mut conn = self.conn.lock().await;
        let row = sqlx::query_with::<MySql, _>(&stmt.sql, values)
            .fetch_optional(&mut **conn)
            .await;
        row.map(|row| row.map(QueryResult::from))
            .map_err(query_failed)
    }

    async fn query_all(&self, stmt: Statement) -> std::result::Result<Vec<QueryResult>, DbErr> {
        let values = bound_values(stmt.values);
        let mut conn = self.conn.lock().await;
        let rows = sqlx::query_with::<MySql, _>(&stmt.sql, values)
            .fetch_all(&mut **conn)
            .await
            .map_err(query_failed)?;
        Ok(rows.into_iter().map(QueryResult::from).collect())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::get_initialized_db;
    use crate::sql_lockout_handler::tests as doors;
    use crate::sql_tables::{DbConnection, init_table};
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::requests::CreateUserRequest;
    use lldap_domain::types::Attribute;
    use lldap_domain_handlers::enforcement::{
        Attempt, Door, NOT_LOADED, PolicyCache, Refusal, UNREADABLE, admit, admit_at_kdc_with,
        default_item_checks, fill_policy_cache, gave_up, item_checks, resolve_items,
        start_policy_filler, user_written,
    };
    use lldap_domain_handlers::handler::{PolicyBackendHandler, UserBackendHandler};
    use lldap_domain_handlers::lockout::{DURATION, Lockout, THRESHOLD, lock_clock};
    use lldap_domain_handlers::logging::LogKind;
    use lldap_domain_handlers::password::{
        PasswordChangeError, PasswordSync, change_password_everywhere, min_length_for_ou_key,
        min_length_for_user, min_length_in_ou, min_length_of,
    };
    use lldap_domain_handlers::policies::CreatePolicyRequest;
    use lldap_test_utils::enforcement::EnforcementGuard;
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use sea_orm::DatabaseTransaction;
    use serial_test::serial;
    use std::time::Instant;

    const OU: &str = "k2ou";
    const SIGN_INS: [&str; 7] = ["k2a", "k2b", "k2c", "k2d", "k2e", "k2f", "k2g"];
    const DOORS: [Door; 5] = [
        Door::LdapBind,
        Door::SimpleLogin,
        Door::WebLogin,
        Door::Refresh,
        Door::TokenUse,
    ];
    const WITHIN: Duration = Duration::from_secs(4);
    const AT_ONCE: Duration = Duration::from_secs(1);
    const ACQUIRE: Duration = Duration::from_secs(10);
    const PG_DEFAULTS: &str = "SELECT bool_and(setting = reset_val) FROM pg_settings \
                               WHERE name IN ('lock_timeout', 'statement_timeout')";
    const POLICY_UNREAD: &str = "the password policy could not be read; try again";

    type Answer = (&'static str, std::result::Result<(), Refusal>, bool);
    type Round = (&'static str, Vec<Answer>, bool, (usize, usize));

    #[test]
    fn test_the_statement_bound_follows_the_servers_flavour() {
        let rows = [
            ("9.7.0", "max_execution_time", "1500"),
            ("8.0.39", "max_execution_time", "1500"),
            ("12.3.1-MariaDB-ubu2404", "max_statement_time", "1.5"),
            ("10.6.18-mariadb-log", "max_statement_time", "1.5"),
        ];
        for (version, variable, limit) in rows {
            let bound = statement_bound(version);
            assert_eq!(bound, (variable, limit.to_owned()), "{version}");
        }
        assert_eq!(
            (SERVER_BOUND.as_millis(), SERVER_BOUND.as_secs().max(1)),
            (1_500, 1)
        );
    }

    #[test]
    fn test_the_databases_own_bound_is_told_from_other_errors() {
        type Row = (&'static str, Option<&'static str>, Option<u16>, bool);
        let rows: [Row; 8] = [
            ("PostgreSQL lock_timeout", Some("55P03"), None, true),
            ("PostgreSQL statement_timeout", Some("57014"), None, true),
            ("PostgreSQL deadlock", Some("40P01"), None, false),
            ("MySQL lock_wait_timeout", Some("HY000"), Some(1205), true),
            ("MySQL max_execution_time", Some("HY000"), Some(3024), true),
            ("MariaDB statement time", Some("70100"), Some(1969), true),
            ("MySQL duplicate key", Some("23000"), Some(1062), false),
            ("no code", None, None, false),
        ];
        for (label, code, number, reached) in rows {
            assert_eq!(bound_reached(code, number), reached, "{label}");
        }
    }

    async fn user_in(handler: &SqlBackendHandler, name: &str) {
        let ou = Attribute {
            name: "ou".into(),
            value: OU.to_owned().into(),
        };
        let request = CreateUserRequest {
            user_id: UserId::new(name),
            email: format!("{name}@example.com").into(),
            attributes: vec![ou],
            ..Default::default()
        };
        handler.create_user(request).await.unwrap();
    }

    /// The users' OU links a policy, so the read reaches `ou_policies` and then `policies`.
    async fn signing_in(pool: &DbConnection, names: &[&str]) -> SqlBackendHandler {
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        for name in names {
            user_in(&handler, name).await;
        }
        let request = CreatePolicyRequest {
            name: "k2hold".to_owned(),
            description: String::new(),
            items: Default::default(),
        };
        let id = handler.create_policy(request).await.unwrap();
        handler.set_ou_policy(OU, id).await.unwrap();
        handler
    }

    #[tokio::test]
    #[serial]
    async fn test_a_sign_in_waiting_for_sqlites_one_connection_is_refused_within_the_bound() {
        let log = LogGuard::install_on_this_thread();
        let pool = get_initialized_db().await;
        let handler = signing_in(&pool, &["k2lite"]).await;
        let _guard = EnforcementGuard::allowing(&["k2lite"], "login-hours");
        let (held, holding) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move {
            let txn = pool.begin().await.unwrap();
            held.send(()).unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            txn.rollback().await.unwrap();
        });
        holding.await.unwrap();
        let user = UserId::new("k2lite");
        log.recorder().take_events();
        let started = Instant::now();
        let answered = admit(&handler, &Attempt::new(&user, Door::LdapBind)).await;
        let took = started.elapsed();
        holder.await.unwrap();
        let next = Instant::now();
        let read = handler.get_user_details(&user).await.map(|u| u.user_id);
        let next = next.elapsed();
        let rows: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.actor.as_deref() == Some("k2lite"))
            .map(|e| (e.kind, e.success, e.detail))
            .collect();
        let refusal = Refusal {
            item: UNREADABLE,
            door: Door::LdapBind,
        };
        let row = (LogKind::Bind, false, Some("policy: unreadable".to_owned()));
        assert_eq!(
            (answered, rows, (took >= POLICY_READ_WAIT, took < WITHIN)),
            (Err(refusal), vec![row], (true, true)),
            "the one connection held: refused at the bound, with the door's one row"
        );
        assert_eq!(
            (read.ok(), next < AT_ONCE),
            (Some(user), true),
            "the refused read left nothing held"
        );
    }

    fn timed(took: Duration) -> (bool, bool) {
        (took >= POLICY_READ_WAIT, took < WITHIN)
    }

    #[tokio::test]
    #[serial]
    async fn test_a_minimum_read_waiting_for_sqlites_one_connection_is_refused_within_the_bound() {
        type Row = (
            &'static str,
            std::result::Result<usize, String>,
            (bool, bool),
        );
        let log = LogGuard::install_on_this_thread();
        let pool = get_initialized_db().await;
        let handler = signing_in(&pool, &["e3lite"]).await;
        let (held, holding) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move {
            let txn = pool.begin().await.unwrap();
            held.send(()).unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            txn.rollback().await.unwrap();
        });
        holding.await.unwrap();
        let user = UserId::new("e3lite");
        let _ = doors::rows(&log, &[]);
        let mut got: Vec<Row> = Vec::new();
        let started = Instant::now();
        let changed = min_length_of(&handler, &user).await;
        got.push((
            "user",
            changed.map_err(|e| e.to_string()),
            timed(started.elapsed()),
        ));
        let started = Instant::now();
        let added = min_length_in_ou(&handler, OU, &user, LogKind::UserCreate).await;
        got.push((
            "OU",
            added.map_err(|e| e.to_string()),
            timed(started.elapsed()),
        ));
        let written = doors::rows(&log, &[LogKind::PasswordChange, LogKind::UserCreate]);
        holder.await.unwrap();
        let next = Instant::now();
        let read = min_length_for_user(&handler, &user).await.ok();
        let next = next.elapsed();
        let refused = || Err(POLICY_UNREAD.to_owned());
        let row = |kind| {
            (
                kind,
                Some("e3lite".to_owned()),
                Some(POLICY_UNREAD.to_owned()),
            )
        };
        assert_eq!(
            (got, written),
            (
                vec![
                    ("user", refused(), (true, true)),
                    ("OU", refused(), (true, true))
                ],
                vec![row(LogKind::PasswordChange), row(LogKind::UserCreate)]
            ),
            "the one connection held: each minimum refused at the bound, with its door's one row"
        );
        assert_eq!(
            (read, next < AT_ONCE),
            (Some(8), true),
            "the refused reads left nothing held"
        );
    }

    enum Holder {
        Postgres(DatabaseTransaction),
        MySql(PoolConnection<MySql>),
    }

    impl Holder {
        async fn take(pool: &DbConnection, table: &str) -> Self {
            if pool.get_database_backend() == DbBackend::MySql {
                let mut conn = pool.get_mysql_connection_pool().acquire().await.unwrap();
                let lock = format!("LOCK TABLES {table} WRITE");
                sqlx::Executor::execute(&mut *conn, lock.as_str())
                    .await
                    .unwrap();
                return Self::MySql(conn);
            }
            let txn = pool.begin().await.unwrap();
            let lock = format!("LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE");
            txn.execute_unprepared(&lock).await.unwrap();
            Self::Postgres(txn)
        }

        async fn release(self) {
            match self {
                Self::MySql(mut conn) => {
                    sqlx::Executor::execute(&mut *conn, "UNLOCK TABLES")
                        .await
                        .unwrap();
                }
                Self::Postgres(txn) => txn.rollback().await.unwrap(),
            }
        }
    }

    fn sign_ins() -> impl Iterator<Item = (&'static str, Door)> {
        SIGN_INS.into_iter().zip(DOORS.into_iter().cycle())
    }

    async fn seven_at_once(handler: &SqlBackendHandler) -> Vec<Answer> {
        let started = Instant::now();
        let at_once = |(name, door): (&'static str, Door)| {
            let handler = handler.clone();
            tokio::spawn(async move {
                let user = UserId::new(name);
                let answered = admit(&handler, &Attempt::new(&user, door)).await;
                (name, answered, started.elapsed() < WITHIN)
            })
        };
        let tasks: Vec<_> = sign_ins().map(at_once).collect();
        let mut answers = Vec::new();
        for task in tasks {
            answers.push(task.await.unwrap());
        }
        answers
    }

    fn refused_within_the_bound() -> Vec<Answer> {
        let refused = |(name, door): (&'static str, Door)| {
            let refusal = Refusal {
                item: UNREADABLE,
                door,
            };
            (name, Err(refusal), true)
        };
        sign_ins().map(refused).collect()
    }

    async fn pg_defaults(pool: &DbConnection, count: usize) -> (usize, usize) {
        let pg = pool.get_postgres_connection_pool();
        let mut conns = Vec::new();
        for _ in 0..count {
            let conn = tokio::time::timeout(ACQUIRE, pg.acquire()).await;
            conns.extend(conn.ok().and_then(std::result::Result::ok));
        }
        let mut defaults = 0;
        for conn in &mut conns {
            let (kept,): (bool,) = sqlx::query_as(PG_DEFAULTS)
                .fetch_one(&mut **conn)
                .await
                .unwrap();
            defaults += usize::from(kept);
        }
        (conns.len(), defaults)
    }

    async fn mysql_defaults(pool: &DbConnection, count: usize) -> (usize, usize) {
        let mysql = pool.get_mysql_connection_pool();
        let mut conns = Vec::new();
        for _ in 0..count {
            let conn = tokio::time::timeout(ACQUIRE, mysql.acquire()).await;
            conns.extend(conn.ok().and_then(std::result::Result::ok));
        }
        let mut defaults = 0;
        for conn in &mut conns {
            let (version,): (String,) = sqlx::query_as("SELECT VERSION()")
                .fetch_one(&mut **conn)
                .await
                .unwrap();
            let (statement, _) = statement_bound(&version);
            let same = format!(
                "SELECT CAST(@@SESSION.lock_wait_timeout = @@GLOBAL.lock_wait_timeout \
                 AND @@SESSION.{statement} = @@GLOBAL.{statement} AS SIGNED)"
            );
            let (kept,): (i64,) = sqlx::query_as(same.as_str())
                .fetch_one(&mut **conn)
                .await
                .unwrap();
            defaults += usize::from(kept == 1);
        }
        (conns.len(), defaults)
    }

    async fn pooled_defaults(pool: &DbConnection, count: usize) -> (usize, usize) {
        match pool.get_database_backend() {
            DbBackend::MySql => mysql_defaults(pool, count).await,
            _ => pg_defaults(pool, count).await,
        }
    }

    /// PostgreSQL and MySQL lanes, a pool of six: one holds a policy table, five serve.
    pub(crate) async fn held_table_lane(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        let handler = signing_in(pool, &SIGN_INS).await;
        let _guard = EnforcementGuard::allowing(&SIGN_INS, "login-hours");
        let (mut got, mut want): (Vec<Round>, Vec<Round>) = (Vec::new(), Vec::new());
        for table in ["ou_policies", "policies"] {
            let holder = Holder::take(pool, table).await;
            let answers = seven_at_once(&handler).await;
            let next = Instant::now();
            let unrelated = handler.get_user_details(&UserId::new(SIGN_INS[0])).await;
            let at_once = unrelated.is_ok() && next.elapsed() < AT_ONCE;
            holder.release().await;
            got.push((table, answers, at_once, pooled_defaults(pool, 6).await));
            want.push((table, refused_within_the_bound(), true, (6, 6)));
        }
        assert_eq!(got, want);
    }

    type Changed = (&'static str, std::result::Result<(), String>, bool);

    /// GraphQL `setUserPassword`'s path: the user's minimum, then the change.
    async fn set_user_password(
        handler: &SqlBackendHandler,
        user: &UserId,
    ) -> std::result::Result<(), PasswordChangeError> {
        let min = min_length_of(handler, user).await?;
        change_password_everywhere(handler, user, "Changed-Pass-1", PasswordSync::Off, min).await
    }

    async fn seven_changes(handler: &SqlBackendHandler) -> Vec<Changed> {
        let started = Instant::now();
        let at_once = |name: &'static str| {
            let handler = handler.clone();
            tokio::spawn(async move {
                let changed = set_user_password(&handler, &UserId::new(name)).await;
                (
                    name,
                    changed.map_err(|e| e.to_string()),
                    started.elapsed() < WITHIN,
                )
            })
        };
        let tasks: Vec<_> = SIGN_INS.into_iter().map(at_once).collect();
        let mut answers = Vec::new();
        for task in tasks {
            answers.push(task.await.unwrap());
        }
        answers
    }

    /// PostgreSQL and MySQL lanes, a pool of six: one holds a policy table, five serve.
    pub(crate) async fn held_minimum_lane(pool: &DbConnection) {
        type Added = (std::result::Result<usize, String>, bool);
        type Held = (&'static str, Vec<Changed>, Added, bool, (usize, usize));
        init_table(pool).await.unwrap();
        let handler = signing_in(pool, &SIGN_INS).await;
        let added_by = UserId::new("k2add");
        let (mut got, mut want): (Vec<Held>, Vec<Held>) = (Vec::new(), Vec::new());
        for table in ["ou_policies", "policies"] {
            let holder = Holder::take(pool, table).await;
            let changes = seven_changes(&handler).await;
            let started = Instant::now();
            let added = min_length_in_ou(&handler, OU, &added_by, LogKind::UserCreate).await;
            let added = (added.map_err(|e| e.to_string()), started.elapsed() < WITHIN);
            let next = Instant::now();
            let unrelated = handler.get_user_details(&UserId::new(SIGN_INS[0])).await;
            let at_once = unrelated.is_ok() && next.elapsed() < AT_ONCE;
            holder.release().await;
            got.push((
                table,
                changes,
                added,
                at_once,
                pooled_defaults(pool, 6).await,
            ));
            let refused = SIGN_INS.map(|name| (name, Err(POLICY_UNREAD.to_owned()), true));
            let added = (Err(POLICY_UNREAD.to_owned()), true);
            want.push((table, refused.to_vec(), added, true, (6, 6)));
        }
        assert_eq!(got, want);
    }

    async fn slowest<F: std::future::Future<Output = bool>>(
        read: impl Fn() -> F,
    ) -> (Duration, usize) {
        let (mut largest, mut answered) = (Duration::ZERO, 0);
        for _ in 0..100 {
            let started = Instant::now();
            answered += usize::from(read().await);
            largest = largest.max(started.elapsed());
        }
        (largest, answered)
    }

    /// PostgreSQL and MySQL lanes: each bounded read on an unlocked database, 100 times.
    pub(crate) async fn bounded_read_timing_lane(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        let handler = signing_in(pool, &["k2timed"]).await;
        let (user, cache) = (UserId::new("k2timed"), PolicyCache::new());
        let (h, c, u) = (&handler, &cache, &user);
        let reads = [
            (
                "sign-in",
                slowest(|| async move { resolve_items(h, c, u).await.is_ok() }).await,
            ),
            (
                "password minimum, user",
                slowest(|| async move { matches!(min_length_for_user(h, u).await, Ok(8)) }).await,
            ),
            (
                "password minimum, OU",
                slowest(|| async move { matches!(min_length_for_ou_key(h, OU).await, Ok(8)) })
                    .await,
            ),
        ];
        for (label, (largest, answered)) in reads {
            eprintln!("bounded-read max: {largest:?} ({label}, {answered} of 100 answered)");
        }
        let below =
            reads.map(|(label, (largest, answered))| (label, largest < SERVER_BOUND, answered));
        assert_eq!(
            below,
            [
                ("sign-in", true, 100),
                ("password minimum, user", true, 100),
                ("password minimum, OU", true, 100),
            ]
        );
    }

    async fn fill_waits(pool: &DbConnection) -> bool {
        let backend = pool.get_database_backend();
        let sql = match backend {
            DbBackend::MySql => {
                "SELECT COUNT(*) FROM information_schema.PROCESSLIST \
                 WHERE STATE LIKE 'Waiting for table%' AND DB = DATABASE() \
                 AND ID <> CONNECTION_ID()"
            }
            _ => {
                "SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
                 AND datname = current_database() AND query LIKE '%ou_policies%' \
                 AND pid <> pg_backend_pid()"
            }
        };
        for _ in 0..100 {
            let row = pool.query_one(Statement::from_string(backend, sql)).await;
            let waiting: i64 = row
                .ok()
                .flatten()
                .map_or(0, |row| row.try_get_by_index(0).unwrap_or(0));
            if waiting > 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    /// PostgreSQL and MySQL lanes: a user made while a cache fill waits on the held
    /// `ou_policies`; the KDC's count and verdict are called as `KdcVerdict` calls them.
    pub(crate) async fn held_fill_lane(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        let key = generate_random_private_key();
        let h = doors::own(SqlBackendHandler::new(key, pool.clone()));
        doors::user_in(&h, "e3held", "e3fillou").await;
        doors::policy_on(&h, "e3fillou", &[(THRESHOLD, "3"), (DURATION, "0")]).await;
        let flags = (
            h.policy_cache.lockout_live(),
            h.policy_cache.lockout_unknown(),
        );
        let holder = Holder::take(pool, "ou_policies").await;
        let filler = h.clone();
        let filling =
            tokio::spawn(async move { fill_policy_cache(&filler, filler.policy_cache).await });
        let waited = fill_waits(pool).await;
        doors::user_in(&h, "e3fill", "e3fillou").await;
        let user = UserId::new("e3fill");
        let verdict = || {
            let now = lock_clock().and_utc().timestamp() as u32;
            let attempt = Attempt::at_kdc(&user, Door::KerberosAs, None, now);
            let judged =
                admit_at_kdc_with(h.policy_cache, h.lockout, &attempt, &default_item_checks());
            judged.map_err(|refusal| (refusal.door, refusal.detail()))
        };
        let before = verdict();
        let lock = h.lockout.kdc_state(h.policy_cache, &user);
        let step = lock
            .as_ref()
            .map(|lock| h.lockout.failure(lock, lock_clock()));
        let counted = h.lockout.row(&user).map_or(0, |row| row.fail_count);
        let during = (verdict(), h.policy_cache.marked(&user));
        holder.release().await;
        let filled = tokio::time::timeout(ACQUIRE, filling).await;
        let filled = matches!(filled, Ok(Ok(Ok(()))));
        let after = (verdict(), h.policy_cache.marked(&user));
        let signed_in = doors::bind(&h, "e3fill", doors::RIGHT).await;
        assert_eq!(
            (flags, waited, before, step.is_some(), counted, during),
            (
                (true, false),
                true,
                Ok(()),
                true,
                1,
                (
                    Err((Door::KerberosAs, "policy: not loaded yet".to_owned())),
                    true
                )
            ),
            "during the hold: the fill waits; one wrong password counts, then the user is not loaded"
        );
        assert_eq!(
            (filled, after, signed_in),
            (true, (Ok(()), false), true),
            "after the hold: the fill ends with the user in it, the KDC admits it, it signs in"
        );
    }

    /// MySQL lane, a pool of two: one holds `ou_policies`, the other serves every read.
    pub(crate) async fn mysql_put_back_lane(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        let handler = signing_in(pool, &["k2back"]).await;
        let user = UserId::new("k2back");
        type Row = (&'static str, bool, (usize, usize));
        let mut got: Vec<Row> = Vec::new();
        let answered = handler.bounded_entry(&user).await.is_ok();
        got.push(("answered", answered, mysql_defaults(pool, 2).await));
        let holder = Holder::take(pool, "ou_policies").await;
        let refused = tokio::time::timeout(WITHIN, handler.bounded_entry(&user)).await;
        let refused = matches!(refused, Ok(Err(e)) if gave_up(&e));
        let defaults = mysql_defaults(pool, 1).await;
        got.push(("refused by the server", refused, defaults));
        let early = Duration::from_millis(300);
        let dropped = tokio::time::timeout(early, handler.bounded_entry(&user)).await;
        let defaults = mysql_defaults(pool, 1).await;
        got.push(("dropped by the client", dropped.is_err(), defaults));
        holder.release().await;
        assert_eq!(
            got,
            vec![
                ("answered", true, (2, 2)),
                ("refused by the server", true, (1, 1)),
                ("dropped by the client", true, (1, 1)),
            ]
        );
    }

    /// PostgreSQL and MySQL lanes, a pool of two: a mark pass under a held `ou_policies`, then
    /// the filler.
    pub(crate) async fn mark_pass_lane(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let handler = signing_in(pool, &["k2mark"]).await.with_policy_cache(cache);
        let _guard = EnforcementGuard::allowing(&["k2mark"], "login-hours");
        let (user, counter, checks) = (UserId::new("k2mark"), Lockout::default(), item_checks());
        let kdc = || {
            let attempt = Attempt::at_kdc(&user, Door::KerberosAs, None, 1_700_000_000);
            admit_at_kdc_with(cache, &counter, &attempt, &checks)
        };
        let holder = Holder::take(pool, "ou_policies").await;
        let started = Instant::now();
        user_written(&handler, cache, &user).await;
        let took = started.elapsed();
        let next = Instant::now();
        let unrelated = handler.get_user_details(&user).await.is_ok();
        let at_once = unrelated && next.elapsed() < AT_ONCE;
        let kept = (cache.marked(&user), cache.failed_read());
        let held = (kept, took < WITHIN, at_once);
        let before = kdc();
        holder.release().await;
        let filler = start_policy_filler(handler.clone(), cache);
        let (mut after, until) = (kdc(), Instant::now() + WITHIN);
        while after.is_err() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(50)).await;
            after = kdc();
        }
        filler.abort();
        let not_loaded = Refusal {
            item: NOT_LOADED,
            door: Door::KerberosAs,
        };
        assert_eq!(
            (held, before, after, cache.marked(&user)),
            (((true, false), true, true), Err(not_loaded), Ok(()), false),
            "the pass gave up and kept the mark; the filler's next pass loads the user"
        );
    }
}
