use crate::sql_lockout_handler::numbered;
use crate::sql_used_proofs::hex;
use lldap_domain_model::error::Result;
use lldap_mfa::ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS;
use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};

pub(crate) const CLOCK_TOLERANCE_SECS: i64 = ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS;

/// Records a registration start's id as finished: false when it was taken before, on any server.
pub(crate) async fn take_start_id(
    db: &impl ConnectionTrait,
    id: &[u8; 16],
    expires_at: i64,
) -> Result<bool> {
    let backend = db.get_database_backend();
    let values = vec![Value::from(hex(id)), Value::from(expires_at)];
    match backend {
        DbBackend::MySql => {
            let sql = "INSERT IGNORE INTO used_registration_starts (start_id, expires_at) \
                       VALUES (?, ?)";
            let done = db
                .execute(Statement::from_sql_and_values(backend, sql, values))
                .await?;
            Ok(done.rows_affected() == 1)
        }
        DbBackend::Postgres | DbBackend::Sqlite => {
            let sql = "INSERT INTO used_registration_starts (start_id, expires_at) VALUES (?, ?) \
                       ON CONFLICT (start_id) DO NOTHING RETURNING start_id";
            let statement = Statement::from_sql_and_values(backend, numbered(backend, sql), values);
            Ok(db.query_one(statement).await?.is_some())
        }
    }
}

/// Kept a minute past the expiry, as a used proof is.
pub(crate) async fn prune_used_starts(db: &impl ConnectionTrait, now: i64) -> Result<u64> {
    let backend = db.get_database_backend();
    let sql = "DELETE FROM used_registration_starts WHERE expires_at < ?";
    let before = Value::from(now - CLOCK_TOLERANCE_SECS);
    let statement = Statement::from_sql_and_values(backend, numbered(backend, sql), [before]);
    Ok(db.execute(statement).await?.rows_affected())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::SqlBackendHandler;
    use crate::sql_backend_handler::tests::get_initialized_db;
    use crate::sql_tables::{DbConnection, init_table};
    use lldap_auth::opaque;
    use lldap_domain::types::UserId;
    use lldap_opaque_handler::{OpaqueHandler, registration};
    use pretty_assertions::assert_eq;

    const NOW: i64 = 1_700_000_000;

    pub(crate) async fn kept(db: &DbConnection) -> i64 {
        let count = Statement::from_string(
            db.get_database_backend(),
            "SELECT COUNT(*) FROM used_registration_starts".to_owned(),
        );
        let row = db.query_one(count).await.unwrap().unwrap();
        row.try_get_by_index(0).unwrap()
    }

    pub(crate) fn session(user: &str, session: u8) -> registration::Presenter {
        registration::Presenter {
            actor: UserId::new(user),
            session: [session; 16],
            reset: false,
        }
    }

    pub(crate) async fn web_registration(
        handler: &SqlBackendHandler,
        user: &str,
        password: &str,
        by: &registration::Presenter,
        envelope_key: Option<[u8; 32]>,
    ) -> registration::ClientRegistrationFinishRequest {
        let mut rng = rand::rngs::OsRng;
        let start = opaque::client::registration::start_registration(password.as_bytes(), &mut rng)
            .unwrap();
        let request = registration::ClientRegistrationStartRequest {
            username: UserId::new(user),
            registration_start_request: start.message,
        };
        let response = handler
            .registration_start_by(request, by.clone(), envelope_key)
            .await
            .unwrap();
        let finish = opaque::client::registration::finish_registration(
            start.state,
            password.as_bytes(),
            response.registration_response,
            &mut rng,
        )
        .unwrap();
        registration::ClientRegistrationFinishRequest {
            server_data: response.server_data,
            registration_upload: finish.message,
        }
    }

    pub(crate) async fn used_starts_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let key = opaque::server::generate_random_private_key();
        let handler = SqlBackendHandler::new(key, pool.clone());
        let by = session("admin", 7);
        let request = web_registration(&handler, "bob", "bob-new-1", &by, None).await;
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let (handler, request, by) = (handler.clone(), request.clone(), by.clone());
                tokio::spawn(async move { handler.registration_claim(&request, &by).await })
            })
            .collect();
        let mut taken = 0;
        for task in tasks {
            taken += usize::from(task.await.unwrap().is_ok());
        }
        assert_eq!(
            (taken, kept(pool).await),
            (1, 1),
            "ten finishes of one start at once: one taken, one row"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_ten_finishes_of_one_start_at_once_take_it_once() {
        used_starts_lane(&get_initialized_db().await).await;
    }

    #[tokio::test]
    async fn test_a_start_id_is_taken_once_and_its_row_goes_a_minute_after_it_expires() {
        let db = get_initialized_db().await;
        let (short, long) = ([1u8; 16], [2u8; 16]);
        assert_eq!(
            [
                take_start_id(&db, &short, NOW + 10).await.unwrap(),
                take_start_id(&db, &short, NOW + 10).await.unwrap(),
                take_start_id(&db, &long, NOW + 300).await.unwrap(),
            ],
            [true, false, true]
        );
        let kept_until = NOW + 10 + CLOCK_TOLERANCE_SECS;
        assert_eq!(prune_used_starts(&db, kept_until).await.unwrap(), 0);
        assert_eq!(prune_used_starts(&db, kept_until + 1).await.unwrap(), 1);
        assert_eq!(kept(&db).await, 1, "the unexpired row stays");
        assert!(take_start_id(&db, &short, NOW + 10).await.unwrap());
    }
}
