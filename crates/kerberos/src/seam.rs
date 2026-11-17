use krb5_kdc::host::{
    Denial, HostChange, KerberosStore, KerberosStoreError, LoadedPrincipal, LoadedRealm, Operation,
    PolicyRow, PrincipalRow, RealmBatch, RealmState,
};
use lldap_domain::types::UserId;
use lldap_domain_handlers::kerberos::{self as directory, HostRow};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

// krb5-admin's KADM5_PROTECT_PRINCIPAL (kadm5/codes.rs), which that crate does not export.
pub(crate) const KADM5_PROTECT_PRINCIPAL: u32 = 43_787_550;

/// kerber-rust's host store over the directory's database: its rows, in our types.
pub(crate) struct SqlRealm {
    store: Arc<dyn directory::KerberosStore>,
    started: AtomicBool,
}

impl SqlRealm {
    pub(crate) fn new(store: Arc<dyn directory::KerberosStore>) -> Self {
        Self {
            store,
            started: AtomicBool::new(false),
        }
    }
}

/// The host as KLLDAP drives it: kerber-rust's changes arrive at `commit_change`, our own
/// `change_committing` changes at `write_own`, with the directory rows that commit beside them.
pub(crate) trait Host: KerberosStore {
    fn write_own(&self, change: HostChange, rows: Vec<HostRow>) -> Result<(), KerberosStoreError>;
    fn password_record(&self, user: &UserId) -> Result<Option<Vec<u8>>, KerberosStoreError>;
    /// Until the start pass has committed, only the bootstrap may come from outside.
    fn start_pass_committed(&self);
}

pub(crate) fn committing(
    host: &dyn Host,
) -> impl FnOnce(HostChange) -> Result<(), KerberosStoreError> + '_ {
    committing_with(host, Vec::new())
}

pub(crate) fn committing_with(
    host: &dyn Host,
    rows: Vec<HostRow>,
) -> impl FnOnce(HostChange) -> Result<(), KerberosStoreError> + '_ {
    move |change| {
        if rows.is_empty() && change.rows.is_empty() && change.batch.is_empty() {
            return Ok(());
        }
        host.write_own(change, rows)
    }
}

/// A marked row is a directory user's: an undeclared write is refused, a declared one denied.
pub(crate) fn verdict(change: &HostChange) -> Result<(), KerberosStoreError> {
    if change.intent.operation == Operation::Embedded {
        return Err(KerberosStoreError::Refused(
            "an own write arrived as another's".to_owned(),
        ));
    }
    let Some(row) = change.rows.iter().find(|row| row.host_owned) else {
        return Ok(());
    };
    match change.intent.operation {
        Operation::Bootstrap => Ok(()),
        Operation::Unspecified => Err(KerberosStoreError::Refused(format!(
            "an undeclared write to a directory user's principal: {}",
            row.id
        ))),
        _ => Err(KerberosStoreError::Denied(Denial {
            kadm5_code: KADM5_PROTECT_PRINCIPAL,
            text: format!(
                "{} belongs to a directory user; change it in KLLDAP",
                row.id
            ),
        })),
    }
}

impl KerberosStore for SqlRealm {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        let loaded = self.store.load().map_err(store_error)?;
        Ok(LoadedRealm {
            principals: loaded
                .principals
                .into_iter()
                .map(|p| LoadedPrincipal {
                    name: p.name,
                    record: p.record,
                })
                .collect(),
            policies: loaded
                .policies
                .into_iter()
                .map(|p| PolicyRow {
                    name: p.name,
                    record: p.record,
                })
                .collect(),
            realm: loaded.realm.map(|r| RealmState {
                realm: r.realm,
                state: r.state,
            }),
        })
    }

    fn commit_change(&self, change: HostChange) -> Result<(), KerberosStoreError> {
        if change.intent.operation != Operation::Bootstrap && !self.started.load(Ordering::Acquire)
        {
            return Err(KerberosStoreError::Refused("starting".to_owned()));
        }
        verdict(&change)?;
        self.write(Vec::new(), change.batch)
    }
}

impl Host for SqlRealm {
    fn write_own(&self, change: HostChange, rows: Vec<HostRow>) -> Result<(), KerberosStoreError> {
        self.write(rows, change.batch)
    }

    fn password_record(&self, user: &UserId) -> Result<Option<Vec<u8>>, KerberosStoreError> {
        self.store.password_record(user).map_err(store_error)
    }

    fn start_pass_committed(&self) {
        self.started.store(true, Ordering::Release);
    }
}

impl SqlRealm {
    fn write(&self, rows: Vec<HostRow>, batch: RealmBatch) -> Result<(), KerberosStoreError> {
        let upsert_principals = batch
            .upsert_principals
            .into_iter()
            .map(principal_row)
            .collect::<Result<_, _>>()?;
        self.store
            .commit_with(
                rows,
                directory::RealmBatch {
                    upsert_principals,
                    delete_principals: batch.delete_principals,
                    put_policies: batch
                        .put_policies
                        .into_iter()
                        .map(|p| directory::PolicyRow {
                            name: p.name,
                            record: p.record,
                        })
                        .collect(),
                    delete_policies: batch.delete_policies,
                    realm: batch.realm.map(|r| directory::RealmState {
                        realm: r.realm,
                        state: r.state,
                    }),
                },
            )
            .map_err(store_error)
    }
}

fn principal_row(row: PrincipalRow) -> Result<directory::PrincipalRow, KerberosStoreError> {
    let kvno = i32::try_from(row.kvno).map_err(|_| {
        KerberosStoreError::Refused(format!(
            "{}: key version {} is too large",
            row.name, row.kvno
        ))
    })?;
    Ok(directory::PrincipalRow {
        name: row.name,
        record: row.record,
        has_keys: row.has_keys,
        disabled: row.disabled,
        kvno,
        expiration: row.expiration.map(time),
        password_expiration: row.password_expiration.map(time),
        policy: row.policy,
        modified_date: time(row.modified_date),
        alias_target: row.alias_target,
    })
}

fn time(seconds: u32) -> chrono::NaiveDateTime {
    chrono::DateTime::from_timestamp(i64::from(seconds), 0)
        .unwrap_or_default()
        .naive_utc()
}

fn store_error(e: directory::KerberosStoreError) -> KerberosStoreError {
    match e {
        directory::KerberosStoreError::NotReady(why) => KerberosStoreError::NotReady(why),
        directory::KerberosStoreError::Failed(why) => KerberosStoreError::Failed(why),
        directory::KerberosStoreError::Refused(why) => KerberosStoreError::Refused(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot;
    use crate::embedded::EmbeddedKerberos;
    use crate::embedded::tests::{TempRealm, unmarked};
    use krb5_kdc::Error as StoreError;
    use krb5_kdc::host::{Caller, RowChange, WriteIntent, conformance};
    use krb5_types::PrincipalName;
    use lldap_domain::types::UserId;
    use lldap_domain_handlers::kerberos::KerberosSync;
    use lldap_sql_backend_handler::{
        KerberosCommitterHandle, sql_tables::init_table, start_unregistered_committer,
    };
    use pretty_assertions::assert_eq;
    use sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, TransactionTrait,
    };
    use serial_test::serial;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::runtime::Runtime;

    type Connect<'a> = &'a dyn Fn(usize, &Runtime) -> DatabaseConnection;

    struct Nothing;

    impl directory::KerberosStore for Nothing {
        fn load(&self) -> Result<directory::LoadedRealm, directory::KerberosStoreError> {
            Ok(directory::LoadedRealm {
                principals: vec![],
                policies: vec![],
                realm: None,
            })
        }

        fn commit(&self, _: directory::RealmBatch) -> Result<(), directory::KerberosStoreError> {
            Ok(())
        }
    }

    #[test]
    fn test_only_the_bootstrap_comes_in_before_the_start_pass() {
        let change = |operation| HostChange {
            intent: WriteIntent::new(operation, Caller::Embedder),
            rows: vec![],
            prepared: None,
            batch: RealmBatch::default(),
        };
        let realm = SqlRealm::new(Arc::new(Nothing));
        for (label, operation, ok) in [
            ("a kadmin write while starting", Operation::Modify, false),
            (
                "an undeclared write while starting",
                Operation::Unspecified,
                false,
            ),
            ("the bootstrap while starting", Operation::Bootstrap, true),
        ] {
            assert_eq!(
                realm.commit_change(change(operation)).is_ok(),
                ok,
                "{label}"
            );
        }
        realm.start_pass_committed();
        for (label, operation, ok) in [
            ("a kadmin write after the pass", Operation::Modify, true),
            ("an own write at commit_change", Operation::Embedded, false),
        ] {
            assert_eq!(
                realm.commit_change(change(operation)).is_ok(),
                ok,
                "{label}"
            );
        }
    }

    fn conformance_on(connect: Connect) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let committers: Mutex<Vec<KerberosCommitterHandle>> = Mutex::default();
        let made = AtomicUsize::new(0);
        let new_host = || -> (Arc<dyn KerberosStore>, conformance::OwnCommit) {
            let pool = connect(made.fetch_add(1, Ordering::Relaxed), &runtime);
            let committer = runtime.block_on(async {
                init_table(&pool).await.unwrap();
                start_unregistered_committer(pool)
            });
            let store = committer.store();
            committers.lock().unwrap().push(committer);
            let realm = Arc::new(SqlRealm::new(store));
            realm.start_pass_committed();
            let own = Arc::clone(&realm);
            let commit: conformance::OwnCommit =
                Arc::new(move |change| own.write_own(change, Vec::new()));
            (realm as Arc<dyn KerberosStore>, commit)
        };
        let rows = conformance::run_own(&new_host);
        for row in &rows {
            match &row.outcome {
                Ok(()) => println!("ROW {} PASS", row.name),
                Err(e) => println!("ROW {} FAIL {e}", row.name),
            }
        }
        let failed: Vec<_> = rows
            .iter()
            .filter_map(|row| row.outcome.as_ref().err().map(|e| (row.name, e)))
            .collect();
        assert_eq!((rows.len(), failed), (18, Vec::new()));
    }

    fn runtime() -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    type Reconnect<'a> = &'a dyn Fn(&Runtime) -> DatabaseConnection;

    fn committer_on(
        connect: Reconnect,
        runtime: &Runtime,
    ) -> (KerberosCommitterHandle, DatabaseConnection) {
        let pool = connect(runtime);
        runtime.block_on(async {
            init_table(&pool).await.unwrap();
            (start_unregistered_committer(pool.clone()), pool)
        })
    }

    fn sql(pool: &DatabaseConnection, runtime: &Runtime, statement: &str) {
        runtime
            .block_on(pool.execute_unprepared(statement))
            .unwrap();
    }

    fn sqlite_one_connection(url: &str, runtime: &Runtime) -> DatabaseConnection {
        let mut opts = ConnectOptions::new(url.to_owned());
        opts.max_connections(1).sqlx_logging(false);
        runtime.block_on(Database::connect(opts)).unwrap()
    }

    fn add_user(pool: &DatabaseConnection, runtime: &Runtime, user: &str) {
        sql(
            pool,
            runtime,
            &format!(
                "INSERT INTO users (user_id, email, lowercase_email, creation_date, uuid, \
                 modified_date, password_modified_date) VALUES ('{user}', '{user}@ex.com', \
                 '{user}@ex.com', '2026-01-01 00:00:00', 'uuid-{user}', \
                 '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
            ),
        );
    }

    fn answer(out: Result<Result<(), StoreError>, StoreError>) -> &'static str {
        match out.and_then(|done| done) {
            Ok(()) => "written",
            Err(StoreError::Host(KerberosStoreError::Refused(_))) => "refused",
            Err(StoreError::Host(KerberosStoreError::Denied(Denial {
                kadm5_code: KADM5_PROTECT_PRINCIPAL,
                ..
            }))) => "denied",
            Err(_) => "another error",
        }
    }

    fn state(store: &krb5_kdc::SharedDump, user: &str) -> Option<(bool, bool)> {
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]);
        let guard = store.read().unwrap();
        let principal = guard.get_name(&name)?;
        Some((principal.host_owned(), principal.locked()))
    }

    // U0.bootstrap, mark-create, unspecified, mark-restart and the stragglers, on one database.
    fn owned_rows_on(connect: Reconnect) {
        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let (committer, pool) = committer_on(connect, &runtime);
        for user in ["bob", "gone", "carol", "dave"] {
            add_user(&pool, &runtime, user);
        }
        let host = {
            let host = Arc::new(SqlRealm::new(committer.store()));
            host.start_pass_committed();
            host
        };
        let opened = boot::open_store(&temp.settings, &profile, host.clone()).unwrap();
        assert!(
            host.load().unwrap().realm.is_some(),
            "the bootstrap was written"
        );
        let store = krb5_kdc::shared_dump(opened);
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        for user in ["bob", "gone", "carol"] {
            runtime
                .block_on(embedded.sync_principal(&UserId::new(user), "A-Password-1"))
                .unwrap();
        }
        unmarked(&embedded, "dave", false);
        let bob = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["bob"]);
        let held = host.load().unwrap();
        let kadmin = Caller::Kadmind {
            client: "admin/admin@EXAMPLE.COM".to_owned(),
            initial: false,
            changepw_service: false,
            self_service: false,
        };
        let undeclared = store
            .write()
            .unwrap()
            .change(|s| s.set_status(&bob, true, 0, "test"));
        let declared = store.write().unwrap().change_as(
            WriteIntent::new(Operation::Modify, kadmin),
            None,
            |s| s.set_status(&bob, true, 0, "test"),
        );
        assert_eq!(
            (answer(undeclared), answer(declared), state(&store, "bob")),
            ("refused", "denied", Some((true, false)))
        );
        assert!(host.load().unwrap() == held, "the database is unchanged");
        sql(&pool, &runtime, "DELETE FROM users WHERE user_id = 'gone'");

        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
        let (committer, _pool) = committer_on(connect, &runtime);
        let host = {
            let host = Arc::new(SqlRealm::new(committer.store()));
            host.start_pass_committed();
            host
        };
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        let users = vec![
            (UserId::new("bob"), true),
            (UserId::new("carol"), false),
            (UserId::new("dave"), false),
        ];
        let pass = runtime
            .block_on(embedded.start_pass(users.clone()))
            .unwrap();
        let after: Vec<_> = ["bob", "gone", "carol", "dave"]
            .into_iter()
            .map(|user| (user, state(&store, user)))
            .collect();
        assert_eq!(
            (pass.marked, pass.removed, pass.disabled, after),
            (
                0,
                1,
                1,
                vec![
                    ("bob", Some((true, false))),
                    ("gone", None),
                    ("carol", None),
                    ("dave", Some((false, true))),
                ]
            )
        );
        let swept = host.load().unwrap();
        let again = runtime.block_on(embedded.start_pass(users)).unwrap();
        assert_eq!(
            (again.marked, again.removed, again.disabled),
            (0, 0, 0),
            "a second start writes nothing"
        );
        assert!(host.load().unwrap() == swept, "the database is unchanged");
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_owned_rows_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-owned-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("u0.db").display());
        owned_rows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    fn test_a_held_connection_fails_a_change_within_one_step_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-stall-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("stall.db").display());
        let runtime = runtime();
        let temp = TempRealm::new();
        let (committer, pool) =
            committer_on(&|runtime| sqlite_one_connection(&url, runtime), &runtime);
        add_user(&pool, &runtime, "bob");
        let host = Arc::new(SqlRealm::new(committer.store()));
        host.start_pass_committed();
        let profile = boot::profile(&temp.settings);
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        let bob = UserId::new("bob");
        let sync = |password| runtime.block_on(embedded.sync_principal(&bob, password));
        let kvno = || {
            let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["bob"]);
            let guard = store.read().unwrap();
            guard.get_name(&name)?.keys.iter().map(|k| k.kvno).max()
        };
        sync("A-Password-1").unwrap();
        let (old_kvno, old_rows) = (kvno(), host.load().unwrap());
        let (held_tx, held) = std::sync::mpsc::channel();
        let holder = runtime.spawn({
            let pool = pool.clone();
            async move {
                let txn = pool.begin().await.unwrap();
                let statement = "UPDATE users SET display_name = 'held' WHERE user_id = 'bob'";
                txn.execute_unprepared(statement).await.unwrap();
                held_tx.send(()).unwrap();
                tokio::time::sleep(Duration::from_secs(6)).await;
                txn.rollback().await.unwrap();
            }
        });
        held.recv().unwrap();
        let stalled = sync("A-Password-2").unwrap_err();
        runtime.block_on(holder).unwrap();
        assert_eq!(
            (
                stalled.ends_with("the database did not answer within 5s"),
                kvno(),
                host.load().unwrap() == old_rows
            ),
            (true, old_kvno, true),
            "{stalled}"
        );
        sync("A-Password-3").unwrap();
        assert_eq!(
            kvno(),
            old_kvno.map(|k| k + 1),
            "the next change is written"
        );
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    #[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
    fn test_owned_rows_on_postgres() {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            eprintln!("KLLDAP_TEST_DATABASE_URL is not a postgres URL; skipping");
            return;
        }
        let schema = format!("klldap_owned_{}", std::process::id());
        let made = AtomicBool::new(false);
        owned_rows_on(&|runtime| {
            runtime.block_on(async {
                if !made.swap(true, Ordering::Relaxed) {
                    let admin = Database::connect(url.as_str()).await.unwrap();
                    for sql in [
                        format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
                        format!("CREATE SCHEMA {schema}"),
                    ] {
                        admin.execute_unprepared(&sql).await.unwrap();
                    }
                }
                let mut opts = ConnectOptions::new(url.clone());
                opts.set_schema_search_path(schema.clone())
                    .max_connections(2)
                    .sqlx_logging(false);
                Database::connect(opts).await.unwrap()
            })
        });
    }

    fn count(pool: &DatabaseConnection, runtime: &Runtime, query: &str) -> i64 {
        let statement = sea_orm::Statement::from_string(pool.get_database_backend(), query);
        let row = runtime
            .block_on(pool.query_one(statement))
            .unwrap()
            .unwrap();
        row.try_get::<i64>("", "n").unwrap()
    }

    // X1: a synced user's change, its record and its row in one transaction, or none of them.
    fn one_transaction_on(connect: Reconnect) {
        use lldap_domain_handlers::kerberos::{CommitError, Committed, PasswordCommit};
        use lldap_domain_handlers::logging::{LogKind, event};
        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let (committer, pool) = committer_on(connect, &runtime);
        for user in ["bob", "carol"] {
            sql(
                &pool,
                &runtime,
                &format!(
                    "INSERT INTO users (user_id, email, lowercase_email, creation_date, uuid, \
                     modified_date, password_modified_date) VALUES ('{user}', '{user}@ex.com', \
                     '{user}@ex.com', '2026-01-01 00:00:00', 'uuid-{user}', \
                     '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
                ),
            );
        }
        let host = Arc::new(SqlRealm::new(committer.store()));
        host.start_pass_committed();
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        fn change(user: &str, record: &[u8]) -> PasswordCommit {
            PasswordCommit {
                user: UserId::new(user),
                record: record.to_vec(),
                disabled: false,
                rows: vec![
                    HostRow::SetPassword {
                        user: UserId::new(user),
                        record: record.to_vec(),
                        now: chrono::Utc::now().naive_utc(),
                    },
                    HostRow::Log(event(LogKind::PasswordChange, Some(user), true, None)),
                ],
            }
        }
        fn kvno(store: &krb5_kdc::PrincipalStore, user: &str) -> Option<u32> {
            let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]);
            store.get_name(&name).and_then(|p| p.top_kvno())
        }
        let stored = |user: &str| host.password_record(&UserId::new(user)).unwrap();
        let logs = || {
            count(
                &pool,
                &runtime,
                "SELECT COUNT(*) AS n FROM logs WHERE kind = 'password_change'",
            )
        };

        let done = runtime.block_on(embedded.commit_password(change("bob", b"r1"), "Bob-Pass-1"));
        let reopened = boot::open_store(&temp.settings, &profile, host.clone()).unwrap();
        assert_eq!(
            (
                done,
                stored("bob") == Some(b"r1".to_vec()),
                logs(),
                kvno(&reopened, "bob")
            ),
            (Ok(Committed::Done), true, 1, Some(1)),
            "committed: both new, with its row"
        );

        let carol = runtime.block_on(embedded.commit_password(change("carol", b"c1"), "Carol-1"));
        assert_eq!(carol, Ok(Committed::Done));
        sql(&pool, &runtime, "DELETE FROM users WHERE user_id = 'carol'");
        let gone = runtime.block_on(embedded.commit_password(change("carol", b"c2"), "Carol-2"));
        assert_eq!(
            (gone, kvno(&store.read().unwrap(), "carol"), logs()),
            (Err(CommitError::UserGone), Some(1), 2),
            "the user deleted in between: refused, the keys put back"
        );

        sql(
            &pool,
            &runtime,
            "UPDATE kerberos_realm SET generation = generation + 1",
        );
        let moved = runtime.block_on(embedded.commit_password(change("bob", b"r2"), "Bob-Pass-2"));
        assert_eq!(
            (
                matches!(moved, Err(CommitError::Failed(_))),
                stored("bob") == Some(b"r1".to_vec()),
                logs(),
                kvno(&store.read().unwrap(), "bob")
            ),
            (true, true, 2, Some(1)),
            "the generation moved: failed, both old"
        );
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_one_transaction_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-x1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("x1.db").display());
        one_transaction_on(&|runtime| {
            let mut opts = ConnectOptions::new(url.clone());
            opts.max_connections(1).sqlx_logging(false);
            runtime.block_on(Database::connect(opts)).unwrap()
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    #[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
    fn test_one_transaction_on_postgres() {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            eprintln!("KLLDAP_TEST_DATABASE_URL is not a postgres URL; skipping");
            return;
        }
        let schema = format!("klldap_x1_{}", std::process::id());
        let made = AtomicBool::new(false);
        one_transaction_on(&|runtime| {
            runtime.block_on(async {
                if !made.swap(true, Ordering::Relaxed) {
                    let admin = Database::connect(url.as_str()).await.unwrap();
                    for sql in [
                        format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
                        format!("CREATE SCHEMA {schema}"),
                    ] {
                        admin.execute_unprepared(&sql).await.unwrap();
                    }
                }
                let mut opts = ConnectOptions::new(url.clone());
                opts.set_schema_search_path(schema.clone())
                    .max_connections(2)
                    .sqlx_logging(false);
                Database::connect(opts).await.unwrap()
            })
        });
    }

    #[test]
    fn test_the_verdict_on_each_intent() {
        type Row = (Operation, bool, Result<(), &'static str>);
        let rows: [Row; 8] = [
            (Operation::Unspecified, false, Ok(())),
            (Operation::Modify, false, Ok(())),
            (Operation::Embedded, false, Err("refused")),
            (Operation::Bootstrap, true, Ok(())),
            (Operation::Unspecified, true, Err("refused")),
            (Operation::Modify, true, Err("denied")),
            (Operation::ChangePassword, true, Err("denied")),
            (Operation::Embedded, true, Err("refused")),
        ];
        for (operation, owned, expected) in rows {
            let change = HostChange {
                intent: WriteIntent::new(operation, Caller::Embedder),
                rows: vec![RowChange {
                    id: "bob@EXAMPLE.COM".to_owned(),
                    before: None,
                    after: None,
                    mask: 0,
                    host_owned: owned,
                }],
                prepared: None,
                batch: RealmBatch::default(),
            };
            let got = match verdict(&change) {
                Ok(()) => Ok(()),
                Err(KerberosStoreError::Refused(_)) => Err("refused"),
                Err(KerberosStoreError::Denied(Denial {
                    kadm5_code: KADM5_PROTECT_PRINCIPAL,
                    ..
                })) => Err("denied"),
                Err(_) => Err("other"),
            };
            assert_eq!(got, expected, "{operation:?}, owned {owned}");
        }
    }

    #[test]
    fn test_kerber_rust_conformance_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-conformance-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.clone();
        conformance_on(&move |n, runtime| {
            let url = format!(
                "sqlite://{}?mode=rwc",
                file.join(format!("{n}.db")).display()
            );
            sqlite_one_connection(&url, runtime)
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
    fn test_kerber_rust_conformance_on_postgres() {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            eprintln!("KLLDAP_TEST_DATABASE_URL is not a postgres URL; skipping");
            return;
        }
        conformance_on(&move |n, runtime| {
            let schema = format!("klldap_conformance_{}_{n}", std::process::id());
            runtime.block_on(async {
                let admin = Database::connect(url.as_str()).await.unwrap();
                for sql in [
                    format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
                    format!("CREATE SCHEMA {schema}"),
                ] {
                    admin.execute_unprepared(&sql).await.unwrap();
                }
                let mut opts = ConnectOptions::new(url.clone());
                opts.set_schema_search_path(schema)
                    .max_connections(2)
                    .sqlx_logging(false);
                Database::connect(opts).await.unwrap()
            })
        });
    }

    #[test]
    #[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
    fn test_kerber_rust_conformance_on_mysql() {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        if !url.starts_with("mysql://") {
            eprintln!("KLLDAP_TEST_DATABASE_URL is not a mysql URL; skipping");
            return;
        }
        conformance_on(&move |n, runtime| {
            let db = format!("klldap_conf_{}_{n}", std::process::id());
            runtime.block_on(async {
                let admin_url = format!(
                    "{}/mysql",
                    url.split('?')
                        .next()
                        .unwrap_or(&url)
                        .rsplit_once('/')
                        .unwrap()
                        .0
                );
                let admin = Database::connect(admin_url.as_str()).await.unwrap();
                for sql in [
                    format!("DROP DATABASE IF EXISTS `{db}`"),
                    format!("CREATE DATABASE `{db}`"),
                ] {
                    admin.execute_unprepared(&sql).await.unwrap();
                }
                let db_url = format!(
                    "{}/{db}",
                    url.split('?')
                        .next()
                        .unwrap_or(&url)
                        .rsplit_once('/')
                        .unwrap()
                        .0
                );
                let mut opts = ConnectOptions::new(db_url);
                opts.max_connections(2).sqlx_logging(false);
                Database::connect(opts).await.unwrap()
            })
        });
    }

    fn row(kvno: u32, expiration: Option<u32>) -> PrincipalRow {
        PrincipalRow {
            name: "bob@EXAMPLE.COM".to_owned(),
            record: vec![1, 2],
            has_keys: true,
            disabled: false,
            kvno,
            expiration,
            password_expiration: None,
            policy: Some("default".to_owned()),
            modified_date: 1_767_225_600,
            attributes: 0x80,
            alias_target: None,
        }
    }

    #[test]
    fn test_principal_rows_convert() {
        let when = |s| chrono::DateTime::from_timestamp(s, 0).unwrap().naive_utc();
        let converted = principal_row(row(3, Some(1_798_761_600))).unwrap();
        assert_eq!(
            (
                converted.kvno,
                converted.expiration,
                converted.modified_date,
                converted.policy
            ),
            (
                3,
                Some(when(1_798_761_600)),
                when(1_767_225_600),
                Some("default".to_owned())
            )
        );
        let refused = principal_row(row(u32::MAX, None)).unwrap_err();
        assert!(
            matches!(&refused, KerberosStoreError::Refused(why) if why.contains("key version")),
            "{refused:?}"
        );
    }
}
