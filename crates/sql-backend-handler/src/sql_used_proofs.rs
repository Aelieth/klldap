use crate::sql_lockout_handler::numbered;
use lldap_domain_model::error::Result;
use lldap_mfa::ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS;
use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};

fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Records a proof's id as used: false when it was used before, on any server.
pub(crate) async fn take_proof_id(
    db: &impl ConnectionTrait,
    id: &[u8; 16],
    expires_at: i64,
) -> Result<bool> {
    let backend = db.get_database_backend();
    let values = vec![Value::from(hex(id)), Value::from(expires_at)];
    match backend {
        DbBackend::MySql => {
            let sql = "INSERT IGNORE INTO mfa_used_proofs (proof_id, expires_at) VALUES (?, ?)";
            let done = db
                .execute(Statement::from_sql_and_values(backend, sql, values))
                .await?;
            Ok(done.rows_affected() == 1)
        }
        DbBackend::Postgres | DbBackend::Sqlite => {
            let sql = "INSERT INTO mfa_used_proofs (proof_id, expires_at) VALUES (?, ?) \
                       ON CONFLICT (proof_id) DO NOTHING RETURNING proof_id";
            let statement = Statement::from_sql_and_values(backend, numbered(backend, sql), values);
            Ok(db.query_one(statement).await?.is_some())
        }
    }
}

/// Kept a minute past the proof's expiry, so a server whose clock lags that much still finds it.
pub(crate) async fn prune_used_proofs(db: &impl ConnectionTrait, now: i64) -> Result<u64> {
    let backend = db.get_database_backend();
    let sql = numbered(backend, "DELETE FROM mfa_used_proofs WHERE expires_at < ?");
    let before = Value::from(now - ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS);
    let done = db
        .execute(Statement::from_sql_and_values(backend, sql, [before]))
        .await?;
    Ok(done.rows_affected())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::get_initialized_db;
    use crate::sql_tables::{DbConnection, init_table};
    use pretty_assertions::assert_eq;

    const NOW: i64 = 1_700_000_000;

    async fn kept(db: &DbConnection) -> i64 {
        let count = Statement::from_string(
            db.get_database_backend(),
            "SELECT COUNT(*) FROM mfa_used_proofs".to_owned(),
        );
        let row = db.query_one(count).await.unwrap().unwrap();
        row.try_get_by_index(0).unwrap()
    }

    pub(crate) async fn used_proofs_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let id = [0x5au8; 16];
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move { take_proof_id(&pool, &id, NOW + 300).await })
            })
            .collect();
        let mut taken = 0;
        for task in tasks {
            taken += usize::from(task.await.unwrap().unwrap());
        }
        assert_eq!(
            (taken, kept(pool).await),
            (1, 1),
            "ten uses of one proof at once: one accepted, one row"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_one_proof_used_at_once_on_sqlites_one_connection_is_taken_once() {
        used_proofs_lane(&get_initialized_db().await).await;
    }

    #[tokio::test]
    async fn test_an_id_is_taken_once_and_its_row_goes_a_minute_after_it_expires() {
        let db = get_initialized_db().await;
        let (short, long) = ([1u8; 16], [2u8; 16]);
        assert_eq!(
            [
                take_proof_id(&db, &short, NOW + 10).await.unwrap(),
                take_proof_id(&db, &short, NOW + 10).await.unwrap(),
                take_proof_id(&db, &long, NOW + 300).await.unwrap(),
            ],
            [true, false, true]
        );
        let tolerance = ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS;
        assert_eq!(
            prune_used_proofs(&db, NOW + 10 + tolerance).await.unwrap(),
            0
        );
        assert_eq!(
            prune_used_proofs(&db, NOW + 11 + tolerance).await.unwrap(),
            1
        );
        assert_eq!(kept(&db).await, 1, "the unexpired row stays");
        assert!(take_proof_id(&db, &short, NOW + 10).await.unwrap());
    }
}
