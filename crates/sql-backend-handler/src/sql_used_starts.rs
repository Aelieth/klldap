use crate::sql_lockout_handler::numbered;
use crate::sql_used_proofs::hex;
use lldap_domain_model::error::Result;
use lldap_mfa::ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS;
use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};

pub(crate) const CLOCK_TOLERANCE_SECS: i64 = ENROLLMENT_PROOF_CLOCK_TOLERANCE_SECS;

/// The starts whose finish is taken once, each kind in its own table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartKind {
    Registration,
    Login,
}

impl StartKind {
    pub(crate) const ALL: [Self; 2] = [Self::Registration, Self::Login];

    fn table(self) -> &'static str {
        match self {
            Self::Registration => "used_registration_starts",
            Self::Login => "used_login_starts",
        }
    }
}

/// Records a start's id as finished: false when it was taken before, on any server.
pub(crate) async fn take_start_id(
    db: &impl ConnectionTrait,
    kind: StartKind,
    id: &[u8; 16],
    expires_at: i64,
) -> Result<bool> {
    let (backend, table) = (db.get_database_backend(), kind.table());
    let values = vec![Value::from(hex(id)), Value::from(expires_at)];
    match backend {
        DbBackend::MySql => {
            let sql = format!("INSERT IGNORE INTO {table} (start_id, expires_at) VALUES (?, ?)");
            let done = db
                .execute(Statement::from_sql_and_values(backend, sql, values))
                .await?;
            Ok(done.rows_affected() == 1)
        }
        DbBackend::Postgres | DbBackend::Sqlite => {
            let sql = format!(
                "INSERT INTO {table} (start_id, expires_at) VALUES (?, ?) \
                 ON CONFLICT (start_id) DO NOTHING RETURNING start_id"
            );
            let statement =
                Statement::from_sql_and_values(backend, numbered(backend, &sql), values);
            Ok(db.query_one(statement).await?.is_some())
        }
    }
}

/// Kept a minute past the expiry, as a used proof is.
pub(crate) async fn prune_used_starts(db: &impl ConnectionTrait, now: i64) -> Result<u64> {
    let backend = db.get_database_backend();
    let mut pruned = 0;
    for kind in StartKind::ALL {
        let sql = format!("DELETE FROM {} WHERE expires_at < ?", kind.table());
        let before = Value::from(now - CLOCK_TOLERANCE_SECS);
        let statement = Statement::from_sql_and_values(backend, numbered(backend, &sql), [before]);
        pruned += db.execute(statement).await?.rows_affected();
    }
    Ok(pruned)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::SqlBackendHandler;
    use crate::sql_backend_handler::tests::{get_initialized_db, insert_user};
    use crate::sql_lockout_handler::tests as doors;
    use crate::sql_tables::{DbConnection, init_table};
    use lldap_auth::opaque;
    use lldap_domain::types::UserId;
    use lldap_opaque_handler::{OpaqueHandler, registration};
    use pretty_assertions::assert_eq;

    const NOW: i64 = 1_700_000_000;

    pub(crate) async fn kept_of(db: &DbConnection, kind: StartKind) -> i64 {
        let count = Statement::from_string(
            db.get_database_backend(),
            format!("SELECT COUNT(*) FROM {}", kind.table()),
        );
        let row = db.query_one(count).await.unwrap().unwrap();
        row.try_get_by_index(0).unwrap()
    }

    pub(crate) async fn kept(db: &DbConnection) -> i64 {
        kept_of(db, StartKind::Registration).await
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
        for kind in StartKind::ALL {
            let db = get_initialized_db().await;
            let (short, long) = ([1u8; 16], [2u8; 16]);
            assert_eq!(
                [
                    take_start_id(&db, kind, &short, NOW + 10).await.unwrap(),
                    take_start_id(&db, kind, &short, NOW + 10).await.unwrap(),
                    take_start_id(&db, kind, &long, NOW + 300).await.unwrap(),
                ],
                [true, false, true],
                "{kind:?}"
            );
            let other = match kind {
                StartKind::Registration => StartKind::Login,
                StartKind::Login => StartKind::Registration,
            };
            assert!(
                take_start_id(&db, other, &short, NOW + 10).await.unwrap(),
                "{kind:?}: the other kind's table holds its own ids"
            );
            let kept_until = NOW + 10 + CLOCK_TOLERANCE_SECS;
            assert_eq!(prune_used_starts(&db, kept_until).await.unwrap(), 0);
            assert_eq!(
                prune_used_starts(&db, kept_until + 1).await.unwrap(),
                2,
                "{kind:?}: each table's expired row"
            );
            assert_eq!(
                kept_of(&db, kind).await,
                1,
                "{kind:?}: the unexpired row stays"
            );
            assert!(take_start_id(&db, kind, &short, NOW + 10).await.unwrap());
        }
    }

    pub(crate) async fn login_starts_lane(pool: &DbConnection) {
        init_table(pool).await.expect("init");
        let key = opaque::server::generate_random_private_key();
        let handler = SqlBackendHandler::new(key, pool.clone());
        insert_user(&handler, "bob", "bob-pass-1").await;
        let started = doors::start(&handler, "bob", "bob-pass-1").await;
        let request = doors::finish_request(started, "bob-pass-1", None).unwrap();
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let (handler, request) = (handler.clone(), request.clone());
                tokio::spawn(async move { handler.login_finish(request).await })
            })
            .collect();
        let mut signed_in = 0;
        for task in tasks {
            signed_in += usize::from(task.await.unwrap().is_ok());
        }
        assert_eq!(
            (signed_in, kept_of(pool, StartKind::Login).await),
            (1, 1),
            "ten finishes of one login start at once: one signs in, one row"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn test_ten_finishes_of_one_login_start_at_once_take_it_once() {
        login_starts_lane(&get_initialized_db().await).await;
    }
}
