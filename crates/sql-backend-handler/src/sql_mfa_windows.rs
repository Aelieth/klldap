use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_lockout_handler::numbered;
use crate::sql_tables::DbConnection;
use crate::sql_totp_steps::lock_conflict;
use lldap_domain::types::UserId;
use lldap_domain_handlers::kdc_proof::ProofWindow;
use lldap_domain_handlers::logging;
use lldap_domain_model::error::Result;
use sea_orm::{ConnectionTrait, DbBackend, IsolationLevel, Statement, TransactionTrait, Value};
use tracing::warn;

pub(crate) const PROOF_NOT_STORED: &str = "proof not stored";

const EXTEND: &str = "UPDATE mfa_windows SET until_at = ? \
                      WHERE user_id = ? AND peer = ? AND until_at >= ? AND until_at < ?";

fn open_sql(backend: DbBackend) -> &'static str {
    match backend {
        DbBackend::MySql => {
            "INSERT IGNORE INTO mfa_windows (user_id, peer, opened_at, until_at) \
             VALUES (?, ?, ?, ?)"
        }
        DbBackend::Postgres | DbBackend::Sqlite => {
            "INSERT INTO mfa_windows (user_id, peer, opened_at, until_at) \
             VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING"
        }
    }
}

fn statement(backend: DbBackend, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(backend, numbered(backend, sql), values)
}

/// The window still open at `now` reaches `now + window`; else a new one opens. Two servers
/// at once may leave two overlapping rows, and any row that covers a request admits it.
async fn open_window(
    db: &impl ConnectionTrait,
    user: &UserId,
    peer: &str,
    now: i64,
    until: i64,
) -> Result<()> {
    let backend = db.get_database_backend();
    let (user, peer) = (
        Value::from(user.as_str().to_owned()),
        Value::from(peer.to_owned()),
    );
    let values = vec![
        Value::from(until),
        user.clone(),
        peer.clone(),
        Value::from(now),
        Value::from(until),
    ];
    let extended = db.execute(statement(backend, EXTEND, values)).await?;
    if extended.rows_affected() > 0 {
        return Ok(());
    }
    let values = vec![user, peer, Value::from(now), Value::from(until)];
    db.execute(statement(backend, open_sql(backend), values))
        .await?;
    Ok(())
}

/// Read committed on MySQL and MariaDB, so the search takes no gap locks.
async fn mysql_open(
    db: &DbConnection,
    user: &UserId,
    peer: &str,
    now: i64,
    until: i64,
) -> Result<()> {
    let committed = Some(IsolationLevel::ReadCommitted);
    let txn = db.begin_with_config(committed, None).await?;
    match open_window(&txn, user, peer, now, until).await {
        Ok(()) => Ok(txn.commit().await?),
        Err(e) => {
            let _ = txn.rollback().await;
            Err(e)
        }
    }
}

pub(crate) async fn note_window(
    db: &DbConnection,
    user: &UserId,
    peer: &str,
    now: i64,
    until: i64,
) -> Result<()> {
    if db.get_database_backend() != DbBackend::MySql {
        return open_window(db, user, peer, now, until).await;
    }
    match mysql_open(db, user, peer, now, until).await {
        Err(e) if lock_conflict(&e) => mysql_open(db, user, peer, now, until).await,
        opened => opened,
    }
}

const WINDOWS: &str = "SELECT user_id, peer, opened_at, until_at FROM mfa_windows";
/// The rows after one in the order of the table's key: the user, the address, the opening.
const LATER: &str = "user_id > ? OR (user_id = ? AND (peer > ? OR (peer = ? AND opened_at > ?)))";

pub(crate) async fn read_windows(
    db: &impl ConnectionTrait,
    user: Option<&UserId>,
) -> Result<Vec<(UserId, ProofWindow)>> {
    let backend = db.get_database_backend();
    let query = match user {
        Some(user) => statement(
            backend,
            &format!("{WINDOWS} WHERE user_id = ?"),
            vec![Value::from(user.as_str().to_owned())],
        ),
        None => Statement::from_string(backend, WINDOWS.to_owned()),
    };
    windows_of(db, query).await
}

/// One page of everyone's windows in key order, the rows after `after`.
pub(crate) async fn read_windows_after(
    db: &impl ConnectionTrait,
    after: Option<&(UserId, ProofWindow)>,
    limit: usize,
) -> Result<Vec<(UserId, ProofWindow)>> {
    let backend = db.get_database_backend();
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let page = format!("ORDER BY user_id, peer, opened_at LIMIT {limit}");
    let query = match after {
        Some((user, window)) => {
            let user = Value::from(user.as_str().to_owned());
            let peer = Value::from(window.peer.clone());
            let opened = Value::from(window.opened_at);
            statement(
                backend,
                &format!("{WINDOWS} WHERE {LATER} {page}"),
                vec![user.clone(), user, peer.clone(), peer, opened],
            )
        }
        None => Statement::from_string(backend, format!("{WINDOWS} {page}")),
    };
    windows_of(db, query).await
}

async fn windows_of(
    db: &impl ConnectionTrait,
    query: Statement,
) -> Result<Vec<(UserId, ProofWindow)>> {
    let rows = db.query_all(query).await?;
    let of_row = |row: &sea_orm::QueryResult| -> Result<(UserId, ProofWindow)> {
        let user: String = row.try_get_by_index(0)?;
        let opened = ProofWindow {
            peer: row.try_get_by_index(1)?,
            opened_at: row.try_get_by_index(2)?,
            until_at: row.try_get_by_index(3)?,
        };
        Ok((UserId::new(&user), opened))
    };
    rows.iter().map(of_row).collect()
}

/// A change of the user's factor, or of every user's (`None`), ends the proofs made with it.
pub(crate) async fn clear_windows(db: &impl ConnectionTrait, user: Option<&UserId>) -> Result<()> {
    let backend = db.get_database_backend();
    let gone = match user {
        Some(user) => statement(
            backend,
            "DELETE FROM mfa_windows WHERE user_id = ?",
            vec![Value::from(user.as_str().to_owned())],
        ),
        None => Statement::from_string(backend, "DELETE FROM mfa_windows".to_owned()),
    };
    db.execute(gone).await?;
    Ok(())
}

pub(crate) async fn prune_windows(db: &DbConnection, before: i64) -> Result<u64> {
    let backend = db.get_database_backend();
    let old = statement(
        backend,
        "DELETE FROM mfa_windows WHERE until_at < ?",
        vec![Value::from(before)],
    );
    if backend != DbBackend::MySql {
        return Ok(db.execute(old).await?.rows_affected());
    }
    let txn = db
        .begin_with_config(Some(IsolationLevel::ReadCommitted), None)
        .await?;
    let pruned = txn.execute(old).await?.rows_affected();
    txn.commit().await?;
    Ok(pruned)
}

pub(crate) fn with_proof(detail: &str, stored: bool) -> String {
    match stored {
        true => detail.to_owned(),
        false => format!("{detail}; {PROOF_NOT_STORED}"),
    }
}

impl SqlBackendHandler {
    /// A password and a code proven at a directory door open Kerberos for the window. After
    /// the sign-in, outside any transaction; false when the write failed.
    pub async fn note_proof(&self, user: &UserId, now: i64) -> bool {
        let Some(settings) = self.proofs else {
            return true;
        };
        let peer = settings.peer_of(logging::current_request().peer);
        let until = now.saturating_add(settings.window);
        match note_window(&self.sql_pool, user, &peer, now, until).await {
            Ok(()) => {
                self.note_codes_written();
                let opened = ProofWindow {
                    opened_at: now,
                    until_at: until,
                    peer,
                };
                self.policy_cache.put_window(user, opened);
                true
            }
            Err(e) => {
                warn!(r#"The second factor's proof for "{user}" was not stored: {e}"#);
                false
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::{get_initialized_db, insert_user_no_password};
    use crate::sql_lockout_handler::tests as doors;
    use crate::sql_mfa_handler::{pin_clock, set_enrollment_clock};
    use crate::sql_tables::init_table;
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::types::{LoginOutcome, MFA_TYPE_TOTP};
    use lldap_domain_handlers::enforcement::{PolicyCache, fill_policy_cache};
    use lldap_domain_handlers::handler::{MfaBackendHandler, UserBackendHandler};
    use lldap_domain_handlers::kdc_proof::{ProofSettings, ProofVerdict, kdc_verdict, proof_at_as};
    use lldap_domain_handlers::logging::{
        LogKind, Protocol, RequestMeta, with_request, without_session,
    };
    use lldap_domain_handlers::mfa::{ENABLE_MFA, MfaPolicy, MfaResetReason};
    use lldap_mfa::{format_code, totp_code};
    use lldap_opaque_handler::register_password;
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const NOW: i64 = 1_770_000_015;
    const WINDOW: i64 = 600;

    fn settings() -> ProofSettings {
        ProofSettings::new(600, false, 3600)
    }

    async fn spans(db: &DbConnection, user: &str) -> Vec<(i64, i64, String)> {
        let rows = read_windows(db, Some(&UserId::new(user))).await.unwrap();
        let spans = rows
            .into_iter()
            .map(|(_, w)| (w.opened_at, w.until_at, w.peer));
        let mut spans: Vec<_> = spans.collect();
        spans.sort();
        spans
    }

    async fn kerberos_handler() -> SqlBackendHandler {
        let handler = doors::handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        handler.with_proofs(Some(settings()))
    }

    fn code(seed: &[u8], at: i64) -> String {
        format_code(totp_code(seed, at as u64).unwrap())
    }

    #[tokio::test]
    #[serial]
    async fn test_a_replaced_factor_ends_the_users_windows() {
        let (_clock, at) = doors::pinned();
        let handler = kerberos_handler().await;
        doors::user_in(&handler, "e2kreplace", "e2kreplaceou").await;
        let user = UserId::new("e2kreplace");
        let seed = doors::enroll(&handler, "e2kreplace", at).await;
        let db = handler.sql_pool.clone();
        let earlier = NOW - 120;
        note_window(&db, &user, "192.0.2.9", earlier, earlier + WINDOW)
            .await
            .unwrap();
        let open = spans(&db, "e2kreplace").await;
        let ([current, _], _) = doors::codes(&seed, at);
        let restart = handler
            .start_totp_enrollment(&user, Some(current), None)
            .await
            .unwrap();
        let new_seed = lldap_mfa::seed_from_base32(&restart.secret_base32).unwrap();
        handler
            .finish_totp_enrollment(&user, &restart.state, &code(&new_seed, at as i64))
            .await
            .unwrap();
        let finish = at as i64;
        assert_eq!(
            (open, spans(&db, "e2kreplace").await),
            (
                vec![
                    (earlier, earlier + WINDOW, "192.0.2.9".to_owned()),
                    (finish, finish + WINDOW, String::new())
                ],
                vec![(finish, finish + WINDOW, String::new())]
            ),
            "the enrollment's own window and an earlier one are open; a replacement of the factor ends \
             both, and its finish opens its own"
        );
    }

    #[tokio::test]
    async fn test_a_proof_opens_a_window_one_inside_extends_it_one_after_opens_another() {
        let db = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), db.clone());
        insert_user_no_password(&handler, "e2kspan").await;
        let user = UserId::new("e2kspan");
        let peer = "192.0.2.7";
        for (at, from) in [
            (NOW, ""),
            (NOW + 300, ""),
            (NOW + 1000, ""),
            (NOW + 1000, peer),
        ] {
            note_window(&db, &user, from, at, at + WINDOW)
                .await
                .unwrap();
        }
        assert_eq!(
            spans(&db, "e2kspan").await,
            vec![
                (NOW, NOW + 900, String::new()),
                (NOW + 1000, NOW + 1600, String::new()),
                (NOW + 1000, NOW + 1600, peer.to_owned())
            ],
            "a proof inside the open window extends it; one after it, or from another address, \
             opens another"
        );
        assert_eq!(
            prune_windows(&db, NOW + 1600).await.unwrap(),
            1,
            "only a window that ended before the cut goes"
        );
        handler.delete_user(&user).await.unwrap();
        assert_eq!(
            spans(&db, "e2kspan").await,
            vec![],
            "the user's windows go with them"
        );
    }

    pub(crate) async fn windows_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        insert_user_no_password(&handler, "e2klane").await;
        let user = UserId::new("e2klane");
        let at_once = |at: i64| {
            let tasks: Vec<_> = (0..10)
                .map(|_| {
                    let (pool, user) = (pool.clone(), user.clone());
                    tokio::spawn(
                        async move { note_window(&pool, &user, "", at, at + WINDOW).await },
                    )
                })
                .collect();
            async move {
                for task in tasks {
                    task.await.unwrap().unwrap();
                }
            }
        };
        at_once(NOW).await;
        let first = spans(pool, "e2klane").await;
        at_once(NOW + 300).await;
        let later = spans(pool, "e2klane").await;
        let reach = later.iter().all(|(_, until, _)| *until == NOW + 900);
        let from = later.first().map(|(opened, _, _)| *opened);
        assert_eq!(
            (first, reach, from),
            (vec![(NOW, NOW + WINDOW, String::new())], true, Some(NOW)),
            "ten proofs at once open one window; ten inside it all reach its new end, an \
             overlapping row allowed"
        );
        window_pages_lane(pool).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_proofs_at_once_on_sqlites_one_connection_open_one_window_and_extend_it() {
        windows_lane(&get_initialized_db().await).await;
    }

    /// Two servers on one database, an enrolled user filled on both.
    struct Two {
        a: SqlBackendHandler,
        here: &'static PolicyCache,
        there: &'static PolicyCache,
        user: UserId,
    }

    async fn two_servers(pool: &DbConnection, name: &str) -> Two {
        init_table(pool).await.expect("init");
        let key = generate_random_private_key();
        let server = |cache: &'static PolicyCache| {
            SqlBackendHandler::new(key.clone(), pool.clone())
                .with_policy_cache(cache)
                .with_mfa_setting(Some(MfaPolicy::Enrolled))
                .with_proofs(Some(settings()))
        };
        let here: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let there: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let (a, b) = (server(here), server(there));
        insert_user_no_password(&a, name).await;
        let user = UserId::new(name);
        let totp = Some(MFA_TYPE_TOTP.to_owned());
        let enrolled = a.write_mfa_columns(&user, Some("sealed".to_owned()), totp);
        enrolled.await.unwrap();
        fill_policy_cache(&a, here).await.unwrap();
        fill_policy_cache(&b, there).await.unwrap();
        there.serve_windows(Arc::new(b), tokio::runtime::Handle::current());
        Two {
            a,
            here,
            there,
            user,
        }
    }

    /// The KDC's own path at `NOW`: its question, and a refusal's re-read.
    fn kinit_at(cache: &'static PolicyCache, user: &UserId) -> ProofVerdict {
        kdc_verdict(cache, user, proof_at_as(cache, user, NOW, None))
    }

    async fn until_answered(cache: &PolicyCache, user: &UserId, want: ProofVerdict) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while proof_at_as(cache, user, NOW, None) != want && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub(crate) async fn two_servers_lane(pool: &DbConnection) {
        let two = two_servers(pool, "e2ktwo").await;
        let stored = two.a.note_proof(&two.user, NOW).await;
        let refused = kinit_at(two.there, &two.user);
        until_answered(two.there, &two.user, ProofVerdict::Admitted).await;
        assert_eq!(
            (
                stored,
                kinit_at(two.here, &two.user),
                refused,
                kinit_at(two.there, &two.user)
            ),
            (
                true,
                ProofVerdict::Admitted,
                ProofVerdict::NoFreshProof,
                ProofVerdict::Admitted
            ),
            "the server that took the proof at once; the other after the re-read its refusal asks"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_proof_on_one_server_admits_a_kinit_on_the_other_after_its_reread() {
        two_servers_lane(&get_initialized_db().await).await;
    }

    pub(crate) async fn reset_elsewhere_lane(pool: &DbConnection) {
        let two = two_servers(pool, "e2kreset").await;
        let reason = MfaResetReason::Administrative;
        two.a.reset_user_mfa(&two.user, reason).await.unwrap();
        let refused = kinit_at(two.there, &two.user);
        until_answered(two.there, &two.user, ProofVerdict::NotAsked).await;
        assert_eq!(
            (refused, kinit_at(two.there, &two.user)),
            (ProofVerdict::NoFreshProof, ProofVerdict::NotAsked),
            "a factor reset on one server: one refusal at most on the other, whose re-read takes \
             the whole user, then today's kinit"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_factor_reset_on_one_server_ends_the_refusal_on_the_other_after_one_reread() {
        reset_elsewhere_lane(&get_initialized_db().await).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_a_proof_belongs_to_its_factor_and_outlives_a_password_change() {
        let _clock = pin_clock(NOW);
        let h = kerberos_handler().await;
        let count = async |name: &str| spans(&h.sql_pool, name).await.len();
        for name in ["e2kfactor", "e2kall"] {
            doors::user_in(&h, name, "e2kou").await;
            doors::enroll(&h, name, NOW as u64).await;
        }
        let user = UserId::new("e2kfactor");
        let enrolled = count("e2kfactor").await;
        register_password(&h, user.clone(), b"Another-Pass-2")
            .await
            .unwrap();
        let after_password = count("e2kfactor").await;
        let reason = MfaResetReason::Administrative;
        h.reset_user_mfa(&user, reason).await.unwrap();
        let after_reset = (count("e2kfactor").await, count("e2kall").await);
        h.clear_all_mfa().await.unwrap();
        assert_eq!(
            (enrolled, after_password, after_reset, count("e2kall").await),
            (1, 1, (0, 1), 0),
            "a password change keeps the proof; the user's reset ends theirs only, and a change \
             of the server key ends every one"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_factor_reset_ends_the_writers_kinit_admission_at_once_without_a_fill() {
        let _clock = pin_clock(NOW);
        let h = doors::handler().await.with_proofs(Some(settings()));
        let cache = h.policy_cache;
        doors::policy_on(&h, "e2kmemalways", &[(ENABLE_MFA, "always")]).await;
        doors::policy_on(&h, "e2kmemenabled", &[(ENABLE_MFA, "enabled")]).await;
        let users = [
            ("e2kmemreset", "e2kmemalways"),
            ("e2kmemon", "e2kmemenabled"),
            ("e2kmemall", "e2kmemalways"),
        ];
        for (name, ou) in users {
            doors::user_in(&h, name, ou).await;
            doors::enroll(&h, name, NOW as u64).await;
        }
        fill_policy_cache(&h, cache).await.unwrap();
        let held = |name: &str| {
            let user = UserId::new(name);
            let windows = cache.get().windows_of(&user).len();
            (windows, proof_at_as(cache, &user, NOW, None))
        };
        let filled = users.map(|(name, _)| held(name));
        let reason = MfaResetReason::Administrative;
        h.reset_user_mfa(&UserId::new("e2kmemreset"), reason)
            .await
            .unwrap();
        h.reset_user_mfa(&UserId::new("e2kmemon"), reason)
            .await
            .unwrap();
        let reset = [held("e2kmemreset"), held("e2kmemon")];
        h.clear_all_mfa().await.unwrap();
        fill_policy_cache(&h, cache).await.unwrap();
        let cleared = users.map(|(name, _)| held(name));
        assert_eq!(
            (filled, reset, cleared),
            (
                [(1, ProofVerdict::Admitted); 3],
                [(0, ProofVerdict::NoFreshProof), (0, ProofVerdict::NotAsked)],
                [
                    (0, ProofVerdict::NoFreshProof),
                    (0, ProofVerdict::NotAsked),
                    (0, ProofVerdict::NoFreshProof)
                ]
            ),
            "a reset on the writer, before any fill: the window leaves memory at once, and kinit \
             is refused under always and no longer asked under enabled; a change of the server \
             key ends every window at that fill"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_failed_read_of_a_users_windows_refuses_until_a_good_read_takes_the_table() {
        let _clock = pin_clock(NOW);
        let h = doors::handler().await.with_proofs(Some(settings()));
        let cache = h.policy_cache;
        doors::policy_on(&h, "e2kreadou", &[(ENABLE_MFA, "always")]).await;
        doors::user_in(&h, "e2kread", "e2kreadou").await;
        doors::enroll(&h, "e2kread", NOW as u64).await;
        fill_policy_cache(&h, cache).await.unwrap();
        let user = UserId::new("e2kread");
        let held = || {
            let windows = cache.get().windows_of(&user).len();
            (windows, proof_at_as(cache, &user, NOW, None))
        };
        let run = async |sql: &str| {
            let statement = Statement::from_string(DbBackend::Sqlite, sql.to_owned());
            h.sql_pool.execute(statement).await.unwrap();
        };
        let filled = held();
        run(
            "INSERT INTO mfa_windows (user_id, peer, opened_at, until_at) \
             VALUES ('e2kread', 'e2kbad', 0, 'unreadable')",
        )
        .await;
        run("CREATE TRIGGER e2k_keep_bad BEFORE DELETE ON mfa_windows \
             WHEN old.peer = 'e2kbad' BEGIN SELECT RAISE(IGNORE); END")
        .await;
        let reason = MfaResetReason::Administrative;
        h.reset_user_mfa(&user, reason).await.unwrap();
        let failed = held();
        run("DROP TRIGGER e2k_keep_bad").await;
        run("DELETE FROM mfa_windows WHERE peer = 'e2kbad'").await;
        note_window(&h.sql_pool, &user, "", NOW, NOW + WINDOW)
            .await
            .unwrap();
        doors::user_in(&h, "e2kreadnext", "e2kreadou").await;
        assert_eq!(
            (filled, failed, held()),
            (
                (1, ProofVerdict::Admitted),
                (0, ProofVerdict::NoFreshProof),
                (1, ProofVerdict::Admitted)
            ),
            "the reset's re-read of the windows fails: none in memory, kinit refused, the mark \
             kept; the next write's take reads the table again and its window admits"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_password_and_a_code_at_each_door_open_kerberos_for_the_window() {
        let _clock = pin_clock(NOW);
        let h = kerberos_handler().await;
        doors::user_in(&h, "e2kdoor", "e2kou").await;
        let user = UserId::new("e2kdoor");
        let reach = async || {
            spans(&h.sql_pool, "e2kdoor")
                .await
                .iter()
                .map(|s| s.1)
                .max()
        };
        let seed = doors::enroll(&h, "e2kdoor", NOW as u64).await;
        let mut reached = vec![(true, reach().await)];
        let ldap = RequestMeta {
            protocol: Protocol::Ldap,
            ..RequestMeta::default()
        };
        for (n, door) in ["ldap", "simple", "web", "check"].into_iter().enumerate() {
            let at = NOW + 60 * (n as i64 + 1);
            set_enrollment_clock(Some(at));
            let now_code = code(&seed, at);
            let with_code = format!("{}:{now_code}", doors::RIGHT);
            let web = doors::web(&h, "e2kdoor", doors::RIGHT, Some(&now_code));
            let passed = match door {
                "ldap" => with_request(ldap.clone(), doors::bind(&h, "e2kdoor", &with_code)).await,
                "simple" => doors::bind(&h, "e2kdoor", &with_code).await,
                "web" => web.await.is_ok(),
                _ => without_session(web).await.is_ok(),
            };
            reached.push((passed, reach().await));
        }
        set_enrollment_clock(Some(NOW + 300));
        let current = Some(code(&seed, NOW + 300));
        let start = h.start_totp_enrollment(&user, current, None).await.unwrap();
        let next = lldap_mfa::seed_from_base32(&start.secret_base32).unwrap();
        set_enrollment_clock(Some(NOW + 330));
        let next_code = code(&next, NOW + 330);
        let replaced = h.finish_totp_enrollment(&user, &start.state, &next_code);
        reached.push((replaced.await.is_ok(), reach().await));
        let ends = [600, 660, 720, 780, 840, 930].map(|end| (true, Some(NOW + end)));
        assert_eq!(
            reached,
            ends.to_vec(),
            "the enrolment, the LDAP bind, the simple login, the web login with and without a \
             session, and a replacement each reach the window's end from their own time"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_no_proof_without_a_right_code_and_none_where_kerberos_is_off() {
        let _clock = pin_clock(NOW);
        let h = kerberos_handler().await;
        doors::user_in(&h, "e2knone", "e2kou").await;
        let alone = doors::bind(&h, "e2knone", doors::RIGHT).await;
        let before = spans(&h.sql_pool, "e2knone").await;
        let seed = doors::enroll(&h, "e2knone", NOW as u64).await;
        set_enrollment_clock(Some(NOW + 60));
        let (_, wrong) = doors::codes(&seed, (NOW + 60) as u64);
        let wrong = format!("{}:{wrong}", doors::RIGHT);
        let refused = [
            doors::bind(&h, "e2knone", &wrong).await,
            doors::bind(&h, "e2knone", doors::RIGHT).await,
        ];
        let stopped = doors::web(&h, "e2knone", doors::RIGHT, None).await;
        assert_eq!(
            (
                alone,
                before,
                refused,
                matches!(stopped, Ok(LoginOutcome::TotpRequired))
            ),
            (true, vec![], [false, false], true)
        );
        assert_eq!(
            spans(&h.sql_pool, "e2knone").await,
            vec![(NOW, NOW + WINDOW, String::new())],
            "a password alone, a wrong code and a stop for the code leave the enrolment's window"
        );
        let off = doors::handler().await.with_mfa_policy(MfaPolicy::Enrolled);
        doors::user_in(&off, "e2koff", "e2kou").await;
        let seed = doors::enroll(&off, "e2koff", (NOW + 60) as u64).await;
        set_enrollment_clock(Some(NOW + 120));
        let with_code = format!("{}:{}", doors::RIGHT, code(&seed, NOW + 120));
        assert_eq!(
            (
                doors::bind(&off, "e2koff", &with_code).await,
                spans(&off.sql_pool, "e2koff").await
            ),
            (true, vec![]),
            "where Kerberos is off, nothing is written"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_proof_that_cannot_be_stored_leaves_the_sign_in_standing_and_says_so() {
        let _clock = pin_clock(NOW);
        let log = LogGuard::install_on_this_thread();
        let h = kerberos_handler().await;
        doors::user_in(&h, "e2klost", "e2kou").await;
        let user = UserId::new("e2klost");
        let seed = doors::enroll(&h, "e2klost", NOW as u64).await;
        for (name, on) in [("e2k_no_insert", "INSERT"), ("e2k_no_update", "UPDATE")] {
            let sql = format!(
                "CREATE TRIGGER {name} BEFORE {on} ON mfa_windows \
                 BEGIN SELECT RAISE(ABORT, 'refused'); END"
            );
            let refuse = Statement::from_string(DbBackend::Sqlite, sql);
            h.sql_pool.execute(refuse).await.unwrap();
        }
        let _ = doors::rows(&log, &[]);
        set_enrollment_clock(Some(NOW + 60));
        let with_code = format!("{}:{}", doors::RIGHT, code(&seed, NOW + 60));
        let bound = doors::bind(&h, "e2klost", &with_code).await;
        set_enrollment_clock(Some(NOW + 120));
        let web_code = code(&seed, NOW + 120);
        let web = doors::web(&h, "e2klost", doors::RIGHT, Some(&web_code)).await;
        set_enrollment_clock(Some(NOW + 180));
        let current = Some(code(&seed, NOW + 180));
        let start = h.start_totp_enrollment(&user, current, None).await.unwrap();
        let next = lldap_mfa::seed_from_base32(&start.secret_base32).unwrap();
        set_enrollment_clock(Some(NOW + 210));
        let next_code = code(&next, NOW + 210);
        let replaced = h.finish_totp_enrollment(&user, &start.state, &next_code);
        let replaced = replaced.await.is_ok();
        let kinds = [LogKind::Bind, LogKind::Login, LogKind::MfaEnroll];
        let rows = doors::rows(&log, &kinds);
        let said = |kind: LogKind| {
            rows.iter()
                .rfind(|row| row.0 == kind)
                .and_then(|row| row.2.clone())
        };
        let not_stored = |detail: &str| Some(format!("{detail}; proof not stored"));
        assert_eq!(
            (
                (bound, web.is_ok(), replaced),
                said(LogKind::Bind),
                said(LogKind::Login),
                said(LogKind::MfaEnroll)
            ),
            (
                (true, true, true),
                not_stored("totp"),
                not_stored("totp"),
                not_stored("replaced")
            ),
            "the bind, the web login and a replacement's finish stand, and each one's row says \
             the proof was not stored"
        );
    }

    /// Any backend: everyone's windows a page at a time, the lane's own rows told by their names.
    pub(crate) async fn window_pages_lane(pool: &DbConnection) {
        use lldap_domain_handlers::handler::PolicyBackendHandler;
        init_table(pool).await.expect("init");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let handler = doors::own(handler);
        let stored = [
            ("r1wb", "", NOW),
            ("r1wa", "192.0.2.9", NOW + 2000),
            ("r1wa", "", NOW + 1000),
            ("r1wa", "192.0.2.9", NOW),
            ("r1wa", "", NOW),
        ];
        for name in ["r1wa", "r1wb"] {
            insert_user_no_password(&handler, name).await;
        }
        for (user, peer, at) in stored {
            let user = UserId::new(user);
            note_window(pool, &user, peer, at, at + WINDOW)
                .await
                .unwrap();
        }
        let mut read: Vec<(UserId, ProofWindow)> = Vec::new();
        loop {
            let page = handler.read_proof_windows_after(read.last(), 1).await;
            let page = page.unwrap();
            if page.is_empty() {
                break;
            }
            read.extend(page);
        }
        let ours = read
            .iter()
            .filter(|(user, _)| user.as_str().starts_with("r1w"));
        let keys = ours.map(|(user, w)| (user.as_str(), w.peer.as_str(), w.opened_at));
        assert_eq!(
            keys.collect::<Vec<_>>(),
            vec![
                ("r1wa", "", NOW),
                ("r1wa", "", NOW + 1000),
                ("r1wa", "192.0.2.9", NOW),
                ("r1wa", "192.0.2.9", NOW + 2000),
                ("r1wb", "", NOW),
            ],
            "pages of one: each row once, by the user, then the address, then the opening"
        );
    }
}
