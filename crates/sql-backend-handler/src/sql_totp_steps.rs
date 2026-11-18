use crate::sql_backend_handler::SqlBackendHandler;
use crate::sql_lockout_handler::numbered;
use crate::sql_mfa_handler::now_unix;
use crate::sql_tables::DbConnection;
use lldap_domain::types::UserId;
use lldap_domain_model::error::{DomainError, Result};
use lldap_domain_model::model::{self, TotpStepsColumn};
use lldap_mfa::{TOTP_MAX_ATTEMPTS_PER_STEP, TOTP_STEP_SECS};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, IsolationLevel, QueryFilter, Statement,
    TransactionTrait, Value,
};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// A step's row is kept this many steps, so its mark outlives clocks that differ by less.
pub(crate) const KEPT_STEPS: u64 = 10;
const PRUNE_BOUND: Duration = Duration::from_secs(5);

pub(crate) fn current_step() -> u64 {
    u64::try_from(now_unix()).unwrap_or(0) / TOTP_STEP_SECS
}

fn binds(user: &UserId, step: u64) -> Vec<Value> {
    let step = i64::try_from(step).unwrap_or(i64::MAX);
    vec![Value::from(user.as_str().to_owned()), Value::from(step)]
}

fn statement(backend: DbBackend, sql: &str, user: &UserId, step: u64) -> Statement {
    Statement::from_sql_and_values(backend, numbered(backend, sql), binds(user, step))
}

async fn changed(db: &impl ConnectionTrait, sql: &str, user: &UserId, step: u64) -> Result<bool> {
    let done = db
        .execute(statement(db.get_database_backend(), sql, user, step))
        .await?;
    Ok(done.rows_affected() == 1)
}

async fn returned(db: &impl ConnectionTrait, sql: &str, user: &UserId, step: u64) -> Result<bool> {
    let found = db
        .query_one(statement(db.get_database_backend(), sql, user, step))
        .await?;
    Ok(found.is_some())
}

/// On MySQL and MariaDB: the guarded update, else a new row, else the update once more.
async fn update_or_insert(
    db: &impl ConnectionTrait,
    update: &str,
    insert: &str,
    user: &UserId,
    step: u64,
) -> Result<bool> {
    Ok(changed(db, update, user, step).await?
        || changed(db, insert, user, step).await?
        || changed(db, update, user, step).await?)
}

/// One attempt of the user's allowance in `step`: false once the allowance is spent.
pub(crate) async fn reserve(db: &impl ConnectionTrait, user: &UserId, step: u64) -> Result<bool> {
    let limit = TOTP_MAX_ATTEMPTS_PER_STEP;
    match db.get_database_backend() {
        DbBackend::MySql => {
            let update = format!(
                "UPDATE totp_steps SET failures = failures + 1 \
                 WHERE user_id = ? AND step = ? AND failures < {limit}"
            );
            let insert = "INSERT IGNORE INTO totp_steps (user_id, step, failures, used) \
                          VALUES (?, ?, 1, false)";
            update_or_insert(db, &update, insert, user, step).await
        }
        DbBackend::Postgres | DbBackend::Sqlite => {
            let upsert = format!(
                "INSERT INTO totp_steps (user_id, step, failures, used) VALUES (?, ?, 1, false) \
                 ON CONFLICT (user_id, step) DO UPDATE SET failures = totp_steps.failures + 1 \
                 WHERE totp_steps.failures < {limit} RETURNING failures"
            );
            returned(db, &upsert, user, step).await
        }
    }
}

pub(crate) async fn refund(db: &impl ConnectionTrait, user: &UserId, step: u64) -> Result<()> {
    let sql = "UPDATE totp_steps SET failures = failures - 1 \
               WHERE user_id = ? AND step = ? AND failures > 0";
    changed(db, sql, user, step).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mark {
    Taken,
    Used,
    KeyChanged,
}

const STILL_THE_KEY: &str = "SELECT 1 FROM users WHERE user_id = ? AND totp_secret = ?";

fn still_the_key(backend: DbBackend, user: &UserId, sealed: &str, lock: &str) -> Statement {
    let values = [user.as_str().to_owned(), sealed.to_owned()].map(Value::from);
    let sql = numbered(backend, &format!("{STILL_THE_KEY}{lock}"));
    Statement::from_sql_and_values(backend, sql, values)
}

/// Takes the code of `step` for the user, only while `sealed` is still the user's stored secret.
pub(crate) async fn mark_used(
    db: &DbConnection,
    user: &UserId,
    step: u64,
    sealed: &str,
) -> Result<Mark> {
    if db.get_database_backend() != DbBackend::MySql {
        return mark_in(db, user, step, sealed).await;
    }
    match mysql_mark(db, user, step, sealed).await {
        Err(e) if lock_conflict(&e) => mysql_mark(db, user, step, sealed).await,
        marked => marked,
    }
}

/// MySQL and MariaDB answer a deadlock or a lock wait with "try restarting transaction".
fn lock_conflict(e: &DomainError) -> bool {
    e.to_string().contains("try restarting transaction")
}

/// Read committed, so the mark's searches take no gap locks; the user's row lock stays.
async fn mysql_mark(db: &DbConnection, user: &UserId, step: u64, sealed: &str) -> Result<Mark> {
    let committed = Some(IsolationLevel::ReadCommitted);
    let txn = db.begin_with_config(committed, None).await?;
    match mark_in(&txn, user, step, sealed).await {
        Ok(marked) => {
            txn.commit().await?;
            Ok(marked)
        }
        Err(e) => {
            let _ = txn.rollback().await;
            Err(e)
        }
    }
}

pub(crate) async fn mark_in(
    db: &impl ConnectionTrait,
    user: &UserId,
    step: u64,
    sealed: &str,
) -> Result<Mark> {
    let backend = db.get_database_backend();
    if backend == DbBackend::MySql {
        let held = db.query_one(still_the_key(backend, user, sealed, " FOR UPDATE"));
        if held.await?.is_none() {
            return Ok(Mark::KeyChanged);
        }
        let update = "UPDATE totp_steps SET used = true \
                      WHERE user_id = ? AND step = ? AND used = false";
        let insert = "INSERT IGNORE INTO totp_steps (user_id, step, failures, used) \
                      VALUES (?, ?, 0, true)";
        let taken = update_or_insert(db, update, insert, user, step).await?;
        return Ok(if taken { Mark::Taken } else { Mark::Used });
    }
    let lock = if backend == DbBackend::Postgres {
        " FOR SHARE"
    } else {
        ""
    };
    let upsert = format!(
        "INSERT INTO totp_steps (user_id, step, failures, used) SELECT ?, ?, 0, true \
         WHERE EXISTS ({STILL_THE_KEY}{lock}) \
         ON CONFLICT (user_id, step) DO UPDATE SET used = true \
         WHERE totp_steps.used = false RETURNING used"
    );
    let mut values = binds(user, step);
    values.extend([user.as_str().to_owned(), sealed.to_owned()].map(Value::from));
    let marked = Statement::from_sql_and_values(backend, numbered(backend, &upsert), values);
    if db.query_one(marked).await?.is_some() {
        return Ok(Mark::Taken);
    }
    let held = db
        .query_one(still_the_key(backend, user, sealed, ""))
        .await?;
    Ok(if held.is_some() {
        Mark::Used
    } else {
        Mark::KeyChanged
    })
}

/// A change of the user's factor, or every user's (`None`): marks go, attempts stay.
pub(crate) async fn clear_used(db: &impl ConnectionTrait, user: Option<&UserId>) -> Result<()> {
    let backend = db.get_database_backend();
    let clear = "UPDATE totp_steps SET used = false";
    let statement = match user {
        Some(user) => Statement::from_sql_and_values(
            backend,
            numbered(backend, &format!("{clear} WHERE user_id = ?")),
            [Value::from(user.as_str().to_owned())],
        ),
        None => Statement::from_string(backend, clear.to_owned()),
    };
    db.execute(statement).await?;
    Ok(())
}

pub(crate) async fn prune(db: &DbConnection, now_step: u64) -> Result<u64> {
    let before = i64::try_from(now_step.saturating_sub(KEPT_STEPS)).unwrap_or(i64::MAX);
    let old = model::TotpSteps::delete_many().filter(TotpStepsColumn::Step.lt(before));
    if db.get_database_backend() != DbBackend::MySql {
        return Ok(old.exec(db).await?.rows_affected);
    }
    let txn = db
        .begin_with_config(Some(IsolationLevel::ReadCommitted), None)
        .await?;
    let pruned = old.exec(&txn).await?.rows_affected;
    txn.commit().await?;
    Ok(pruned)
}

impl SqlBackendHandler {
    pub(crate) fn note_codes_written(&self) {
        self.codes_written.store(true, Ordering::Release);
    }

    /// Only when a row was written since the last prune, or once at start.
    pub(crate) async fn prune_totp_steps(&self) -> Result<u64> {
        if !self.codes_written.swap(false, Ordering::AcqRel) {
            return Ok(0);
        }
        let steps = prune(&self.sql_pool, current_step());
        let pruned = tokio::time::timeout(PRUNE_BOUND, steps)
            .await
            .unwrap_or_else(|_| Err(DomainError::InternalError("the prune timed out".to_owned())));
        if pruned.is_err() {
            self.note_codes_written();
        }
        pruned
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::{get_initialized_db, insert_user_no_password};
    use crate::sql_mfa_handler::{TotpRejection, TotpVerdict, pin_clock, set_enrollment_clock};
    use crate::sql_tables::{DbConnection, init_table};
    use lldap_auth::opaque::server::generate_random_private_key;
    use lldap_domain::types::MFA_TYPE_TOTP;
    use lldap_domain_handlers::handler::UserBackendHandler;
    use lldap_mfa::{format_code, totp_code};
    use pretty_assertions::assert_eq;
    use std::sync::{Arc, Mutex};

    const STEP: u64 = 59_000_000;

    async fn keyed(handler: &SqlBackendHandler, user: &UserId, key: &str) {
        let totp = Some(MFA_TYPE_TOTP.to_owned());
        let factor = handler.write_mfa_columns(user, Some(key.to_owned()), totp);
        factor.await.unwrap();
    }

    async fn rows(db: &DbConnection, user: &str) -> Vec<(i64, i16, bool)> {
        let found = model::TotpSteps::find()
            .filter(TotpStepsColumn::UserId.eq(UserId::new(user)))
            .all(db)
            .await
            .unwrap();
        let mut rows: Vec<_> = found
            .into_iter()
            .map(|row| (row.step, row.failures, row.used))
            .collect();
        rows.sort_unstable();
        rows
    }

    pub(crate) async fn concurrency_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        insert_user_no_password(&handler, "e1bcode").await;
        let user = UserId::new("e1bcode");
        keyed(&handler, &user, "key").await;
        let at_once = |n: usize, used: bool| {
            let tasks: Vec<_> = (0..n)
                .map(|_| {
                    let (pool, user) = (pool.clone(), user.clone());
                    tokio::spawn(async move {
                        match used {
                            true => mark_used(&pool, &user, STEP + 1, "key")
                                .await
                                .map(|mark| mark == Mark::Taken),
                            false => reserve(&pool, &user, STEP).await,
                        }
                    })
                })
                .collect();
            async move {
                let mut taken = 0;
                for task in tasks {
                    taken += usize::from(task.await.unwrap().unwrap());
                }
                taken
            }
        };
        assert_eq!(
            (at_once(20, false).await, at_once(10, true).await),
            (usize::from(TOTP_MAX_ATTEMPTS_PER_STEP), 1),
            "twenty wrong codes at once spend five attempts; ten submissions of one code, one use"
        );
        assert_eq!(
            rows(pool, "e1bcode").await,
            vec![
                (59_000_000, i16::from(TOTP_MAX_ATTEMPTS_PER_STEP), false),
                (59_000_001, 0, true)
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_codes_at_once_on_sqlites_one_connection_spend_five_attempts_and_one_use() {
        concurrency_lane(&get_initialized_db().await).await;
    }

    /// Codes checked at once through the doors' own check, on one pinned step each.
    pub(crate) async fn verify_lane(pool: &DbConnection) {
        let at = STEP as i64 * 30 + 5;
        let _clock = pin_clock(at);
        init_table(pool).await.expect("init");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        insert_user_no_password(&handler, "e1bverify").await;
        let user = UserId::new("e1bverify");
        let seed = [7u8; 20];
        let uuid = handler.get_user_details(&user).await.unwrap().uuid;
        let sealed = lldap_mfa::seal_totp_secret(&handler.sealing_key(), uuid.as_str(), &seed);
        keyed(&handler, &user, &sealed.unwrap()).await;
        let code = |at: i64| format_code(totp_code(&seed, at as u64).unwrap());
        let checks = |code: String, n: usize| {
            let tasks: Vec<_> = (0..n)
                .map(|_| {
                    let (handler, user, code) = (handler.clone(), user.clone(), code.clone());
                    tokio::spawn(async move { handler.verify_user_totp(&user, &code).await })
                })
                .collect();
            async move {
                let mut verdicts = Vec::new();
                for task in tasks {
                    verdicts.push(task.await.unwrap().unwrap());
                }
                verdicts
            }
        };
        let count = |verdicts: &[TotpVerdict], want: TotpVerdict| {
            verdicts.iter().filter(|got| **got == want).count()
        };
        let valid = [code(at - 30), code(at), code(at + 30)];
        let wrong = (0..)
            .map(|n| format!("{n:06}"))
            .find(|c| !valid.contains(c));
        let wrongs = checks(wrong.unwrap(), 20).await;
        set_enrollment_clock(Some(at + 30));
        let rights = checks(code(at + 30), 5).await;
        set_enrollment_clock(Some(at + 60));
        let tens = checks(code(at + 60), 10).await;
        let invalid = Err(TotpRejection::Invalid);
        let many = Err(TotpRejection::TooManyAttempts);
        let used = Err(TotpRejection::Replayed);
        assert_eq!(
            (
                count(&wrongs, invalid),
                count(&wrongs, many),
                count(&rights, Ok(())),
                count(&rights, used),
                count(&tens, Ok(()))
            ),
            (5, 15, 1, 4, 1),
            "20 wrong at once: 5 invalid, 15 too many. 5 right at once: 1 taken, 4 already used. \
             10 right at once: each submission reserves first and a step has five reserves, so \
             ten in flight cannot all reach the mark; what the row proves is that exactly one is \
             ever accepted"
        );
    }

    #[tokio::test]
    async fn test_codes_checked_at_once_on_sqlites_one_connection_count_exactly() {
        verify_lane(&get_initialized_db().await).await;
    }

    pub(crate) async fn neighbour_marks_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let users = [UserId::new("e1bann"), UserId::new("e1bben")];
        for user in &users {
            insert_user_no_password(&handler, user.as_str()).await;
            keyed(&handler, user, user.as_str()).await;
        }
        let mut marks = Vec::new();
        for round in 0..20 {
            let reserved = STEP + 10 * round;
            for user in &users {
                assert!(reserve(pool, user, reserved).await.unwrap());
            }
            let steps = [reserved + 1, reserved - 1];
            for (user, step) in users.iter().cloned().zip(steps) {
                let pool = pool.clone();
                marks.push(tokio::spawn(async move {
                    mark_used(&pool, &user, step, user.as_str()).await
                }));
            }
        }
        let mut taken = 0;
        for mark in marks {
            taken += usize::from(mark.await.unwrap().unwrap() == Mark::Taken);
        }
        assert_eq!(taken, 40, "no mark is lost to a lock between neighbours");
    }

    /// A mark meeting a change of the key held open waits for it, then finds the key changed.
    pub(crate) async fn guard_in_flight_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        insert_user_no_password(&handler, "e1bwait").await;
        let user = UserId::new("e1bwait");
        keyed(&handler, &user, "old").await;
        let backend = pool.get_database_backend();
        let change = pool.begin().await.unwrap();
        let sql = numbered(
            backend,
            "UPDATE users SET totp_secret = ? WHERE user_id = ?",
        );
        let values = ["new", "e1bwait"].map(|value| Value::from(value.to_owned()));
        let rekey = Statement::from_sql_and_values(backend, sql, values);
        change.execute(rekey).await.unwrap();
        clear_used(&change, Some(&user)).await.unwrap();
        let mark = {
            let (pool, user) = (pool.clone(), user.clone());
            tokio::spawn(async move { mark_used(&pool, &user, STEP, "old").await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let waited = !mark.is_finished();
        change.commit().await.unwrap();
        let marked = mark.await.unwrap().unwrap();
        assert_eq!(
            (waited, marked, rows(pool, "e1bwait").await),
            (true, Mark::KeyChanged, vec![]),
            "the mark waits on the user's row, then answers key changed and stores nothing"
        );
    }

    pub(crate) async fn key_change_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        insert_user_no_password(&handler, "e1bkey").await;
        let user = UserId::new("e1bkey");
        keyed(&handler, &user, "old").await;
        let marks: Vec<_> = (0..10)
            .map(|n| {
                let (pool, user) = (pool.clone(), user.clone());
                tokio::spawn(async move { mark_used(&pool, &user, STEP + n, "old").await })
            })
            .collect();
        keyed(&handler, &user, "new").await;
        for mark in marks {
            mark.await.unwrap().unwrap();
        }
        let rows = rows(pool, "e1bkey").await;
        assert!(rows.iter().all(|row| !row.2), "{rows:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_a_key_change_racing_marks_on_sqlites_one_connection_leaves_no_old_mark() {
        key_change_lane(&get_initialized_db().await).await;
    }

    #[tokio::test]
    async fn test_each_statement_on_the_step_and_a_deleted_users_rows_go() {
        let db = get_initialized_db().await;
        let handler = SqlBackendHandler::new(generate_random_private_key(), db.clone());
        insert_user_no_password(&handler, "e1bstep").await;
        let user = UserId::new("e1bstep");
        keyed(&handler, &user, "key").await;
        assert!(reserve(&db, &user, STEP).await.unwrap());
        refund(&db, &user, STEP).await.unwrap();
        refund(&db, &user, STEP).await.unwrap();
        assert_eq!(
            (
                mark_used(&db, &user, STEP, "key").await.unwrap(),
                mark_used(&db, &user, STEP, "key").await.unwrap(),
                mark_used(&db, &user, STEP + 1, "gone").await.unwrap(),
                rows(&db, "e1bstep").await
            ),
            (
                Mark::Taken,
                Mark::Used,
                Mark::KeyChanged,
                vec![(59_000_000, 0, true)]
            ),
            "a refund never goes below 0; a step's code is taken once, and only for the stored key"
        );
        keyed(&handler, &user, "next").await;
        assert_eq!(
            rows(&db, "e1bstep").await,
            vec![(59_000_000, 0, false)],
            "a change of the key clears its marks"
        );
        handler.delete_user(&user).await.unwrap();
        assert_eq!(rows(&db, "e1bstep").await, vec![]);
    }

    #[tokio::test]
    async fn test_the_prune_keeps_ten_steps_and_runs_only_after_a_write() {
        let statements = Arc::new(Mutex::new(Vec::<String>::new()));
        let mut db = get_initialized_db().await;
        let seen = statements.clone();
        db.set_metric_callback(move |info| {
            seen.lock().unwrap().push(info.statement.sql.clone());
        });
        let handler = SqlBackendHandler::new(generate_random_private_key(), db.clone());
        insert_user_no_password(&handler, "e1bprune").await;
        let user = UserId::new("e1bprune");
        for step in [STEP - 11, STEP - 10, STEP - 2, STEP] {
            assert!(reserve(&db, &user, step).await.unwrap());
        }
        assert_eq!(prune(&db, STEP).await.unwrap(), 1);
        assert_eq!(
            rows(&db, "e1bprune").await,
            vec![
                (58_999_990, 1, false),
                (58_999_998, 1, false),
                (59_000_000, 1, false)
            ],
            "only the steps before now - 10 go"
        );
        let deletes = || {
            let sql = std::mem::take(&mut *statements.lock().unwrap());
            sql.iter().filter(|s| s.starts_with("DELETE")).count()
        };
        deletes();
        let pruned = [
            handler.prune_totp_steps().await.is_ok(),
            handler.prune_totp_steps().await.is_ok(),
        ];
        assert_eq!(
            (pruned, deletes()),
            ([true, true], 1),
            "one prune at start, then none until a row is written"
        );
        handler.note_codes_written();
        handler.prune_totp_steps().await.unwrap();
        assert_eq!(deletes(), 1, "a row written: the next tick prunes");
    }

    #[tokio::test]
    async fn test_the_bundled_sqlite_takes_an_upsert_with_where_and_returning() {
        let db = get_initialized_db().await;
        let version: String = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT sqlite_version()".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        let parts: Vec<u32> = version.split('.').map(|n| n.parse().unwrap()).collect();
        assert!(parts[..2] >= [3, 35][..], "SQLite {version}");
    }
}
