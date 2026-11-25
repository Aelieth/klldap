use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_lockout_handler::{numbered, quoted};
use crate::sql_log_handler::to_active_model;
use crate::sql_tables::DbConnection;
use chrono::NaiveDateTime;
use lldap_domain::types::UserId;
use lldap_domain_handlers::inactivity::{RECORDING_KEY, RECORDING_OFF, Recorded};
use lldap_domain_handlers::instant::{Timestamp, from_naive, from_stored_text, to_naive};
use lldap_domain_handlers::logging::LogEvent;
use lldap_domain_model::{
    error::{DomainError, Result},
    model,
};
use sea_orm::{ConnectionTrait, DbBackend, DbErr, EntityTrait, Statement, TransactionTrait, Value};

fn statement(backend: DbBackend, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(backend, numbered(backend, sql), values)
}

fn name(user: &UserId) -> Value {
    Value::from(user.as_str().to_owned())
}

fn text(value: &str) -> Value {
    Value::from(value.to_owned())
}

/// The later of the stored success and `at`; a name that is no user stores nothing.
pub(crate) fn success_statement(backend: DbBackend, user: &UserId, at: Timestamp) -> Statement {
    let at = to_naive(at);
    let dual = if backend == DbBackend::MySql {
        " FROM DUAL"
    } else {
        ""
    };
    let insert = format!(
        "INSERT INTO user_activity (user_id, last_success) SELECT ?, ?{dual} \
         WHERE EXISTS (SELECT 1 FROM users WHERE users.user_id = ?)"
    );
    let mut values = vec![name(user), at.into(), name(user)];
    let sql = match backend {
        DbBackend::MySql => {
            values.extend([at.into(), at.into()]);
            format!(
                "{insert} ON DUPLICATE KEY UPDATE \
                 last_success = IF(last_success IS NULL OR last_success < ?, ?, last_success)"
            )
        }
        DbBackend::Postgres | DbBackend::Sqlite => format!(
            "{insert} ON CONFLICT (user_id) DO UPDATE SET last_success = excluded.last_success \
             WHERE user_activity.last_success IS NULL \
             OR user_activity.last_success < excluded.last_success"
        ),
    };
    statement(backend, &sql, values)
}

pub(crate) fn reenable_statement(backend: DbBackend, user: &UserId, at: Timestamp) -> Statement {
    let at = to_naive(at);
    let upsert = match backend {
        DbBackend::MySql => "ON DUPLICATE KEY UPDATE",
        DbBackend::Postgres | DbBackend::Sqlite => "ON CONFLICT (user_id) DO UPDATE SET",
    };
    let sql = format!(
        "INSERT INTO user_activity (user_id, reenabled_at) VALUES (?, ?) {upsert} reenabled_at = ?"
    );
    statement(backend, &sql, vec![name(user), at.into(), at.into()])
}

const ACTIVITY: &str = "SELECT user_id, last_success, reenabled_at FROM user_activity";

pub(crate) async fn read_activity_on(
    db: &impl ConnectionTrait,
    user: Option<&UserId>,
) -> Result<Vec<(UserId, Recorded)>> {
    let backend = db.get_database_backend();
    let query = match user {
        Some(user) => statement(
            backend,
            &format!("{ACTIVITY} WHERE user_id = ?"),
            vec![name(user)],
        ),
        None => Statement::from_string(backend, ACTIVITY.to_owned()),
    };
    activity_of(db, query).await
}

/// One page of everyone's rows in user-id order, the rows after `after`.
pub(crate) async fn read_activity_after_on(
    db: &impl ConnectionTrait,
    after: Option<&UserId>,
    limit: usize,
) -> Result<Vec<(UserId, Recorded)>> {
    let backend = db.get_database_backend();
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let page = format!("ORDER BY user_id LIMIT {limit}");
    let query = match after {
        Some(after) => statement(
            backend,
            &format!("{ACTIVITY} WHERE user_id > ? {page}"),
            vec![name(after)],
        ),
        None => Statement::from_string(backend, format!("{ACTIVITY} {page}")),
    };
    activity_of(db, query).await
}

async fn activity_of(
    db: &impl ConnectionTrait,
    query: Statement,
) -> Result<Vec<(UserId, Recorded)>> {
    let rows = db.query_all(query).await?;
    let of_row = |row: &sea_orm::QueryResult| -> Result<(UserId, Recorded)> {
        let at = |index: usize| -> std::result::Result<Option<Timestamp>, DbErr> {
            let stored = row.try_get_by_index::<Option<NaiveDateTime>>(index)?;
            Ok(stored.map(from_naive))
        };
        let user: String = row.try_get_by_index(0)?;
        let recorded = Recorded {
            last_success: at(1)?,
            reenabled_at: at(2)?,
        };
        Ok((UserId::new(&user), recorded))
    };
    rows.iter().map(of_row).collect()
}

fn recording_text(at: Timestamp) -> String {
    format!("{at:.6}")
}

fn recording_of(stored: &str) -> Result<Option<Timestamp>> {
    if stored == RECORDING_OFF {
        return Ok(None);
    }
    let unread = |e| DomainError::InternalError(format!("{RECORDING_KEY} holds {stored:?}: {e}"));
    let at = from_stored_text(stored).map_err(unread)?;
    Ok(Some(at))
}

pub(crate) async fn recording_in(db: &impl ConnectionTrait) -> Result<Option<Timestamp>> {
    let backend = db.get_database_backend();
    let (key, value, _) = quoted(backend);
    let sql = format!("SELECT {value} FROM system_config WHERE {key} = ?");
    let found = db
        .query_one(statement(backend, &sql, vec![text(RECORDING_KEY)]))
        .await?;
    match found {
        Some(row) => recording_of(&row.try_get_by_index::<String>(0)?),
        None => Ok(None),
    }
}

/// From off to `at` while live, to off when not, each conditional: two servers at once agree.
pub(crate) async fn move_recording(
    db: &impl ConnectionTrait,
    live: bool,
    at: Timestamp,
) -> Result<Option<Timestamp>> {
    let backend = db.get_database_backend();
    let (key, value, _) = quoted(backend);
    let (since, off) = (text(&recording_text(at)), text(RECORDING_OFF));
    let moved = match (live, backend) {
        (false, _) => statement(
            backend,
            &format!("UPDATE system_config SET {value} = ? WHERE {key} = ? AND {value} <> ?"),
            vec![off.clone(), text(RECORDING_KEY), off],
        ),
        (true, DbBackend::MySql) => statement(
            backend,
            &format!(
                "INSERT INTO system_config ({key}, {value}) VALUES (?, ?) \
                 ON DUPLICATE KEY UPDATE {value} = IF({value} = ?, ?, {value})"
            ),
            vec![text(RECORDING_KEY), since.clone(), off, since],
        ),
        (true, DbBackend::Postgres | DbBackend::Sqlite) => statement(
            backend,
            &format!(
                "INSERT INTO system_config ({key}, {value}) VALUES (?, ?) \
                 ON CONFLICT ({key}) DO UPDATE SET {value} = excluded.{value} \
                 WHERE system_config.{value} = ?"
            ),
            vec![text(RECORDING_KEY), since, off],
        ),
    };
    db.execute(moved).await?;
    recording_in(db).await
}

/// The re-enable and its row in one transaction; the host tool has a pool and no handler.
pub async fn reenable_user_on(
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
    txn.execute(reenable_statement(txn.get_database_backend(), user, at))
        .await?;
    model::Logs::insert(to_active_model(row))
        .exec_without_returning(&txn)
        .await?;
    txn.commit().await?;
    Ok(())
}

impl SqlBackendHandler {
    /// A door's success: written while inactivity-days is live, at most once an hour.
    pub(crate) async fn note_activity(&self, user: &UserId, at: Timestamp) {
        self.policy_cache.note_success(self, user, at).await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::get_initialized_db;
    use crate::sql_lockout_handler::tests as doors;
    use crate::sql_opaque_handler::invalid_credentials;
    use crate::sql_tables::init_table;
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::requests::CreateUserRequest;
    use lldap_domain_handlers::enforcement::{INACTIVITY_DAYS, PolicyCache, fill_policy_cache};
    use lldap_domain_handlers::handler::{LockoutBackendHandler, UserBackendHandler};
    use lldap_domain_handlers::inactivity::{
        REENABLED_BY_ADMIN, REENABLED_BY_TOOL, Recording, follow_recording,
    };
    use lldap_domain_handlers::instant::SignedDuration;
    use lldap_domain_handlers::lockout::{LockStore, lock_clock};
    use lldap_domain_handlers::logging::{self, LogKind, RequestMeta, with_request};
    use lldap_test_utils::enforcement::EnforcementGuard;
    use lldap_test_utils::recording_kerberos::DegradedGuard;
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use sea_orm::{ColumnTrait, QueryFilter};
    use serial_test::serial;

    const DAY: i64 = 86_400;
    const WRONG: &str = "Wrong-Pass-1";

    fn exact(seconds: i64, nanos: u32) -> Timestamp {
        Timestamp::new(seconds, nanos as i32).unwrap()
    }

    fn at(seconds: i64) -> Timestamp {
        exact(1_700_000_000 + seconds, 0)
    }

    fn success_at(at: Timestamp) -> Recorded {
        Recorded {
            last_success: Some(at),
            reenabled_at: None,
        }
    }

    fn after(start: Timestamp, seconds: i64) -> Timestamp {
        start + SignedDuration::from_secs(seconds)
    }

    async fn stored(db: &DbConnection, user: &str) -> Vec<Recorded> {
        let rows = read_activity_on(db, Some(&UserId::new(user)))
            .await
            .unwrap();
        rows.into_iter().map(|(_, row)| row).collect()
    }

    async fn reenable_rows(db: &DbConnection) -> Vec<(Option<String>, Option<String>, bool)> {
        let rows = model::Logs::find()
            .filter(model::LogsColumn::Kind.eq("account_reenable"))
            .all(db)
            .await
            .unwrap();
        let rows = rows.into_iter();
        rows.map(|row| (row.target, row.detail, row.success))
            .collect()
    }

    /// Any backend: the statements, the recording row's turns with two at once, the cascade.
    pub(crate) async fn activity_lane(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let request = CreateUserRequest {
            user_id: UserId::new("e6lane"),
            email: "e6lane@example.com".into(),
            ..Default::default()
        };
        handler.create_user(request).await.unwrap();
        let user = UserId::new("e6lane");
        let backend = pool.get_database_backend();
        let columns = "SELECT user_id, last_success, reenabled_at FROM user_activity";
        let made = pool
            .execute(Statement::from_string(backend, columns.to_owned()))
            .await;
        let row = |success: Option<i64>, reenabled: Option<i64>| Recorded {
            last_success: success.map(at),
            reenabled_at: reenabled.map(at),
        };
        let mut got = Vec::new();
        for (step, seconds) in [("a success", 10), ("an older one", 5)] {
            handler.write_success(&user, at(seconds)).await.unwrap();
            got.push((step, stored(pool, "e6lane").await));
        }
        let nobody = handler
            .write_success(&UserId::new("e6nobody"), at(10))
            .await;
        got.push(("no such user", stored(pool, "e6nobody").await));
        pool.execute(reenable_statement(backend, &user, at(20)))
            .await
            .unwrap();
        got.push(("a re-enable", stored(pool, "e6lane").await));
        handler.write_success(&user, at(30)).await.unwrap();
        got.push(("a later success", stored(pool, "e6lane").await));
        assert_eq!(
            (made.is_ok(), nobody.is_ok(), got),
            (
                true,
                true,
                vec![
                    ("a success", vec![row(Some(10), None)]),
                    ("an older one", vec![row(Some(10), None)]),
                    ("no such user", vec![]),
                    ("a re-enable", vec![row(Some(10), Some(20))]),
                    ("a later success", vec![row(Some(30), Some(20))]),
                ]
            )
        );
        let off = recording_in(pool).await.unwrap();
        let (first, second) = tokio::join!(
            move_recording(pool, true, at(100)),
            move_recording(pool, true, at(200))
        );
        let (first, second) = (first.unwrap(), second.unwrap());
        let again = move_recording(pool, true, at(300)).await.unwrap();
        let stopped = move_recording(pool, false, at(400)).await.unwrap();
        let restarted = move_recording(pool, true, at(500)).await.unwrap();
        assert_eq!(
            (
                off,
                first == second,
                [at(100), at(200)].map(Some).contains(&first)
            ),
            (None, true, true),
            "off at the migration; two followers at once agree on the one time stored"
        );
        assert_eq!(
            (again, stopped, restarted),
            (first, None, Some(at(500))),
            "live to live keeps it; live to off is off; off to live is the new time"
        );
        handler.delete_user(&user).await.unwrap();
        assert_eq!(
            stored(pool, "e6lane").await,
            vec![],
            "the row goes with its user"
        );
        activity_pages_lane(pool).await;
    }

    /// Any backend: two servers on one database, each with its own memory.
    pub(crate) async fn two_servers_lane(pool: &DbConnection) {
        init_table(pool).await.unwrap();
        let _guard = EnforcementGuard::default_checks();
        let key = generate_random_private_key();
        let here = doors::own(SqlBackendHandler::new(key.clone(), pool.clone()));
        let there = doors::own(SqlBackendHandler::new(key, pool.clone()));
        doors::user_in(&here, "e6two", "e6twoou").await;
        doors::policy_on(&here, "e6twoou", &[(INACTIVITY_DAYS, "30")]).await;
        let cache = there.policy_cache;
        there.lockout.follow_policies(&there, cache).await.unwrap();
        let recordings = (here.policy_cache.recording(), cache.recording());
        let user = UserId::new("e6two");
        let held = |handler: &SqlBackendHandler| {
            let entries = handler.policy_cache.get();
            entries.facts_of(&user).and_then(|facts| facts.recorded)
        };
        let signed_in = doors::bind(&here, "e6two", doors::RIGHT).await;
        fill_policy_cache(&there, cache).await.unwrap();
        let seen_there = held(&there).and_then(|row| row.last_success);
        there.reenable_user(&user).await.unwrap();
        fill_policy_cache(&here, here.policy_cache).await.unwrap();
        let seen_here = held(&here).and_then(|row| row.reenabled_at);
        assert!(
            matches!(recordings.0, Recording::Since(_)) && recordings.0 == recordings.1,
            "both servers take the one stored time: {recordings:?}"
        );
        assert_eq!(
            (signed_in, seen_there.is_some(), seen_here.is_some()),
            (true, true, true),
            "a sign-in here and a re-enable there reach the other's next fill"
        );
    }

    #[tokio::test]
    async fn test_a_second_start_with_the_item_unset_changes_no_row() {
        let pool = get_initialized_db().await;
        let h = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let changes = async || {
            let total = "SELECT total_changes()".to_owned();
            let row = pool.query_one(Statement::from_string(DbBackend::Sqlite, total));
            let row = row.await.unwrap().unwrap();
            row.try_get_by_index::<i64>(0).unwrap()
        };
        move_recording(&pool, true, at(50)).await.unwrap();
        let mut starts = Vec::new();
        for start in [100, 200] {
            let (cache, before) = (PolicyCache::new(), changes().await);
            follow_recording(&h, &cache, &[], at(start)).await.unwrap();
            starts.push((cache.recording(), changes().await - before));
        }
        assert_eq!(
            (starts, recording_in(&pool).await.unwrap()),
            (vec![(Recording::Off, 1), (Recording::Off, 0)], None),
            "a time left from a live period: the first start sets it off, a second changes nothing"
        );
    }

    #[test]
    fn test_the_recording_time_is_kept_as_utc_text_with_six_digits() {
        let written = [
            ("the epoch", 0, 0, "1970-01-01T00:00:00.000000Z"),
            (
                "nanoseconds are cut",
                1_700_000_000,
                123_456_789,
                "2023-11-14T22:13:20.123456Z",
            ),
            (
                "the last nanosecond of a second",
                1_700_000_000,
                999_999_999,
                "2023-11-14T22:13:20.999999Z",
            ),
            (
                "half a microsecond before 1970",
                -1,
                999_999_500,
                "1969-12-31T23:59:59.999999Z",
            ),
            (
                "a leap day",
                1_835_438_400,
                1_000,
                "2028-02-29T12:00:00.000001Z",
            ),
            (
                "2038-01-19T03:14:08Z",
                2_147_483_648,
                0,
                "2038-01-19T03:14:08.000000Z",
            ),
            (
                "the last instant",
                253_402_207_200,
                999_999_999,
                "9999-12-30T22:00:00.999999Z",
            ),
        ];
        for (label, seconds, nanos, text) in written {
            let cut = exact(seconds, nanos / 1_000 * 1_000);
            assert_eq!(
                (
                    recording_text(exact(seconds, nanos)).as_str(),
                    recording_of(text).unwrap()
                ),
                (text, Some(cut)),
                "{label}"
            );
        }
        let read = [
            ("off", None),
            ("2023-11-14T22:13:20Z", Some((1_700_000_000, 0))),
            ("2023-11-14T22:13:20+00:00", Some((1_700_000_000, 0))),
            (
                "2023-11-14T23:13:20.5+01:00",
                Some((1_700_000_000, 500_000_000)),
            ),
        ];
        for (text, at) in read {
            let at = at.map(|(seconds, nanos)| exact(seconds, nanos));
            assert_eq!(recording_of(text).unwrap(), at, "{text}");
        }
        let unread = recording_of("soon");
        let says = "inactivity_recording_since holds \"soon\": ";
        assert!(
            matches!(&unread, Err(DomainError::InternalError(e)) if e.starts_with(says)),
            "{unread:?}"
        );
    }

    #[tokio::test]
    async fn test_sqlite_keeps_a_success_as_text_with_the_fraction_it_was_given() {
        let pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let user = UserId::new("g1text");
        let request = CreateUserRequest {
            user_id: user.clone(),
            email: "g1text@example.com".into(),
            ..Default::default()
        };
        handler.create_user(request).await.unwrap();
        let rows = [
            (0, 0, "2023-11-14 22:13:20"),
            (1, 120_000_000, "2023-11-14 22:13:21.120"),
            (2, 123_450_000, "2023-11-14 22:13:22.123450"),
            (3, 123_456_789, "2023-11-14 22:13:23.123456789"),
        ];
        for (seconds, nanos, text) in rows {
            let at = exact(1_700_000_000 + seconds, nanos);
            handler.write_success(&user, at).await.unwrap();
            let column = "SELECT last_success FROM user_activity WHERE user_id = 'g1text'";
            let column = Statement::from_string(DbBackend::Sqlite, column.to_owned());
            let kept = pool.query_one(column).await.unwrap().unwrap();
            assert_eq!(
                (
                    kept.try_get_by_index::<String>(0).unwrap().as_str(),
                    stored(&pool, "g1text").await
                ),
                (text, vec![success_at(at)]),
                "{text}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_success_stored_past_the_last_instant_reads_as_the_last_instant() {
        let pool = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let request = CreateUserRequest {
            user_id: UserId::new("g2far"),
            email: "g2far@example.com".into(),
            ..Default::default()
        };
        handler.create_user(request).await.unwrap();
        let far = "INSERT INTO user_activity (user_id, last_success) \
                   VALUES ('g2far', '9999-12-31 23:59:59.999999')";
        let far = Statement::from_string(DbBackend::Sqlite, far.to_owned());
        pool.execute(far).await.unwrap();
        let key = recording_of("9999-12-31T23:59:59.000000Z").unwrap();
        assert_eq!(
            (stored(&pool, "g2far").await, key),
            (vec![success_at(Timestamp::MAX)], Some(Timestamp::MAX)),
            "MySQL's largest DATETIME, as a row and as the recording key's text"
        );
    }

    #[tokio::test]
    async fn test_the_activity_statements_on_sqlite() {
        activity_lane(&get_initialized_db().await).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_two_servers_share_the_activity_on_sqlite() {
        two_servers_lane(&get_initialized_db().await).await;
    }

    async fn sign_in(handler: &SqlBackendHandler, door: &str, user: &str, password: &str) -> bool {
        let meta = match door {
            "ldap" => RequestMeta::ldap(None, None),
            _ => RequestMeta::http(None, None),
        };
        let signed_in = with_request(meta, async {
            match door {
                "web" => doors::web(handler, user, password, None)
                    .await
                    .map(drop)
                    .map_err(drop),
                _ => doors::bind_as(handler, user, password).await.map_err(drop),
            }
        });
        signed_in.await.is_ok()
    }

    #[tokio::test]
    #[serial]
    async fn test_each_password_door_writes_one_success_an_hour_and_none_for_a_refusal() {
        let guard = EnforcementGuard::default_checks();
        let pool = get_initialized_db().await;
        let h = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        doors::user_in(&h, "e6door", "e6doorou").await;
        doors::policy_on(&h, "e6doorou", &[(INACTIVITY_DAYS, "30")]).await;
        let start = lock_clock();
        type Row = (&'static str, i64, &'static str, &'static str, bool, i64);
        let rows: [Row; 7] = [
            (
                "the LDAP bind, first after the start",
                0,
                "ldap",
                doors::RIGHT,
                false,
                0,
            ),
            (
                "the web login inside the hour",
                60,
                "web",
                doors::RIGHT,
                false,
                0,
            ),
            (
                "the simple login an hour on",
                3_600,
                "simple",
                doors::RIGHT,
                false,
                3_600,
            ),
            ("a wrong password", 7_300, "ldap", WRONG, false, 3_600),
            (
                "a degraded refusal after admit",
                7_300,
                "web",
                doors::RIGHT,
                true,
                3_600,
            ),
            (
                "refused as inactive",
                7_300 + 31 * DAY,
                "ldap",
                doors::RIGHT,
                false,
                3_600,
            ),
            (
                "the next one that is due",
                7_300,
                "simple",
                doors::RIGHT,
                false,
                7_300,
            ),
        ];
        for (label, seconds, door, password, degraded, kept) in rows {
            guard.pin_clock(after(start, seconds));
            let down = degraded.then(DegradedGuard::install);
            sign_in(&h, door, "e6door", password).await;
            drop(down);
            let last = stored(&pool, "e6door")
                .await
                .first()
                .map(|r| r.last_success);
            assert_eq!(last, Some(Some(after(start, kept))), "{label}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_an_ou_that_takes_the_item_while_it_is_live_elsewhere_judges_what_was_recorded() {
        let guard = EnforcementGuard::default_checks();
        let pool = get_initialized_db().await;
        let h = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let users = [("e6a", "e6aou"), ("e6idle", "e6bou"), ("e6recent", "e6bou")];
        for (user, ou) in users {
            doors::user_in(&h, user, ou).await;
        }
        let start = lock_clock();
        guard.pin_clock(start);
        doors::policy_on(&h, "e6aou", &[(INACTIVITY_DAYS, "365")]).await;
        guard.pin_clock(after(start, 35 * DAY));
        let recorded = doors::bind(&h, "e6recent", doors::RIGHT).await;
        guard.pin_clock(after(start, 40 * DAY));
        doors::policy_on(&h, "e6bou", &[(INACTIVITY_DAYS, "30")]).await;
        let signed_in = async |user: &str| doors::bind(&h, user, doors::RIGHT).await;
        let at_once = [
            signed_in("e6idle").await,
            signed_in("e6recent").await,
            signed_in("e6a").await,
        ];
        h.reenable_user(&UserId::new("e6idle")).await.unwrap();
        let back = signed_in("e6idle").await;
        assert_eq!(
            (recorded, h.policy_cache.recording()),
            (true, Recording::Since(start)),
            "one server-wide time, from OU A's link; a sign-in in OU B is recorded meanwhile"
        );
        assert_eq!(
            (at_once, back),
            ([false, true, true], true),
            "OU B linked 40 days on with 30: its user with nothing recorded is refused at once, \
             its user with a sign-in 5 days ago is admitted; a re-enable lets the first in"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_no_door_writes_while_the_item_is_off() {
        let _guard = EnforcementGuard::default_checks();
        let pool = get_initialized_db().await;
        let h = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        doors::user_in(&h, "e6quiet", "e6quietou").await;
        doors::policy_on(&h, "e6quietou", &[(INACTIVITY_DAYS, "0")]).await;
        let mut signed_in = Vec::new();
        for door in ["ldap", "simple", "web"] {
            signed_in.push(sign_in(&h, door, "e6quiet", doors::RIGHT).await);
        }
        assert_eq!(
            (signed_in, stored(&pool, "e6quiet").await),
            (vec![true; 3], vec![]),
            "each door signs the user in, and none writes"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_an_inactive_users_right_password_answers_as_a_wrong_one_at_each_password_door() {
        let log = LogGuard::install_on_this_thread();
        let guard = EnforcementGuard::default_checks();
        let h = SqlBackendHandler::new(generate_random_private_key(), get_initialized_db().await);
        doors::user_in(&h, "e6same", "e6sameou").await;
        doors::policy_on(&h, "e6sameou", &[(INACTIVITY_DAYS, "1")]).await;
        let web = async |password: &str| doors::web(&h, "e6same", password, None).await.map(drop);
        let now = Timestamp::now();
        let _ = doors::rows(&log, &[]);
        guard.pin_clock(now);
        let wrong_while_active = web(WRONG).await;
        guard.pin_clock(after(now, 3 * DAY));
        let text = |e: DomainError| e.to_string();
        let mut binds = Vec::new();
        for meta in [RequestMeta::ldap(None, None), RequestMeta::http(None, None)] {
            for password in [doors::RIGHT, WRONG] {
                let bound = with_request(meta.clone(), doors::bind_as(&h, "e6same", password));
                binds.push(bound.await.map_err(text));
            }
        }
        let right_while_inactive = web(doors::RIGHT).await;
        let wrong = Err(invalid_credentials(&UserId::new("e6same")).to_string());
        assert!(wrong_while_active.is_err(), "{wrong_while_active:?}");
        assert_eq!(
            (binds, right_while_inactive),
            (
                vec![wrong.clone(), wrong.clone(), wrong.clone(), wrong],
                wrong_while_active
            ),
            "the LDAP bind and the simple login: the right password of an inactive user and a \
             wrong one, byte for byte; the web login: the right password of the inactive user \
             fails as a wrong one did while active"
        );
        let inactive = Some("policy: inactivity-days (inactive)".to_owned());
        let wrong = Some("invalid credentials".to_owned());
        let rows = doors::rows(&log, &[LogKind::Bind, LogKind::Login]);
        let row = |kind, detail: &Option<String>| (kind, Some("e6same".to_owned()), detail.clone());
        assert_eq!(
            rows,
            vec![
                row(LogKind::Bind, &inactive),
                row(LogKind::Bind, &wrong),
                row(LogKind::Bind, &inactive),
                row(LogKind::Bind, &wrong),
                row(LogKind::Login, &inactive),
            ],
            "only the row tells them apart"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_a_reenable_writes_its_one_row_and_lets_the_inactive_user_in() {
        let guard = EnforcementGuard::default_checks();
        let pool = get_initialized_db().await;
        let h = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        doors::user_in(&h, "e6back", "e6backou").await;
        doors::user_in(&h, "e6tool", "e6backou").await;
        doors::policy_on(&h, "e6backou", &[(INACTIVITY_DAYS, "1")]).await;
        guard.pin_clock(after(Timestamp::now(), 3 * DAY));
        let signed_in = async || {
            let back = doors::bind(&h, "e6back", doors::RIGHT).await;
            (back, doors::bind(&h, "e6tool", doors::RIGHT).await)
        };
        let before = signed_in().await;
        h.reenable_user(&UserId::new("e6back")).await.unwrap();
        let (tool, at) = (UserId::new("e6tool"), lock_clock());
        let detail = Some(REENABLED_BY_TOOL);
        let row = logging::event(LogKind::AccountReenable, Some("e6tool"), true, detail);
        reenable_user_on(&pool, &tool, at, row).await.unwrap();
        fill_policy_cache(&h, h.policy_cache).await.unwrap();
        let after_both = signed_in().await;
        let nobody = h.reenable_user(&UserId::new("e6nobody")).await;
        let reenabled = stored(&pool, "e6tool")
            .await
            .first()
            .map(|r| r.reenabled_at);
        assert_eq!(
            (before, after_both, reenabled),
            ((false, false), (true, true), Some(Some(at))),
            "refused as inactive; each re-enable restarts the count now, the tool's at the next \
             fill"
        );
        let one_each = vec![
            (
                Some("e6back".to_owned()),
                Some(REENABLED_BY_ADMIN.to_owned()),
                true,
            ),
            (
                Some("e6tool".to_owned()),
                Some(REENABLED_BY_TOOL.to_owned()),
                true,
            ),
        ];
        assert_eq!(
            (
                matches!(nobody, Err(DomainError::EntityNotFound(_))),
                reenable_rows(&pool).await
            ),
            (true, one_each),
            "one account_reenable row each; an unknown user writes none"
        );
    }

    /// Any backend: everyone's rows a page at a time, the lane's own rows told by their names.
    pub(crate) async fn activity_pages_lane(pool: &DbConnection) {
        use lldap_domain_handlers::handler::PolicyBackendHandler;
        init_table(pool).await.unwrap();
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let handler = doors::own(handler);
        let names = ["r1e", "r1a", "r1d", "r1b", "r1c"];
        for (seconds, name) in (0..).zip(names) {
            let request = CreateUserRequest {
                user_id: UserId::new(name),
                email: format!("{name}@example.com").into(),
                ..Default::default()
            };
            handler.create_user(request).await.unwrap();
            let user = UserId::new(name);
            handler.write_success(&user, at(seconds)).await.unwrap();
        }
        let mut read: Vec<(UserId, Recorded)> = Vec::new();
        loop {
            let last = read.last().map(|(user, _)| user);
            let page = handler.read_activity_after(last, 2).await.unwrap();
            let short = page.len() < 2;
            read.extend(page);
            if short {
                break;
            }
        }
        let ours = read
            .iter()
            .filter(|(user, _)| names.contains(&user.as_str()));
        let rows = ours.map(|(user, row)| (user.as_str(), *row));
        let row = |name: &'static str, seconds| (name, success_at(at(seconds)));
        assert_eq!(
            rows.collect::<Vec<_>>(),
            vec![
                row("r1a", 1),
                row("r1b", 3),
                row("r1c", 4),
                row("r1d", 2),
                row("r1e", 0)
            ],
            "pages of two: each user's own row once, in user-id order"
        );
    }
}
