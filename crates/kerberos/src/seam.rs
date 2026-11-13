use krb5_kdc::host::{
    KerberosStore, KerberosStoreError, LoadedPrincipal, LoadedRealm, PolicyRow, PrincipalRow,
    RealmBatch, RealmState,
};
use lldap_domain_handlers::kerberos as directory;
use std::sync::Arc;

/// kerber-rust's host store over the directory's database: its rows, in our types.
pub(crate) struct SqlRealm(pub Arc<dyn directory::KerberosStore>);

impl KerberosStore for SqlRealm {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        let loaded = self.0.load().map_err(store_error)?;
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

    fn commit(&self, batch: RealmBatch) -> Result<(), KerberosStoreError> {
        let upsert_principals = batch
            .upsert_principals
            .into_iter()
            .map(principal_row)
            .collect::<Result<_, _>>()?;
        self.0
            .commit(directory::RealmBatch {
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
            })
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
    use krb5_kdc::host::conformance;
    use lldap_sql_backend_handler::{
        KerberosCommitterHandle, sql_tables::init_table, start_unregistered_committer,
    };
    use pretty_assertions::assert_eq;
    use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::runtime::Runtime;

    type Connect<'a> = &'a dyn Fn(usize, &Runtime) -> DatabaseConnection;

    // kerber-rust's own checks of a host store, each on a fresh database and committer.
    fn conformance_on(connect: Connect) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let committers: Mutex<Vec<KerberosCommitterHandle>> = Mutex::default();
        let made = AtomicUsize::new(0);
        let new_store = || -> Arc<dyn KerberosStore> {
            let pool = connect(made.fetch_add(1, Ordering::Relaxed), &runtime);
            let committer = runtime.block_on(async {
                init_table(&pool).await.unwrap();
                start_unregistered_committer(pool)
            });
            let store = committer.store();
            committers.lock().unwrap().push(committer);
            Arc::new(SqlRealm(store))
        };
        let rows = conformance::run(&new_store);
        let failed: Vec<_> = rows
            .iter()
            .filter_map(|row| row.outcome.as_ref().err().map(|e| (row.name, e)))
            .collect();
        assert_eq!((rows.len(), failed), (8, Vec::new()));
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
            let mut opts = ConnectOptions::new(url);
            opts.max_connections(1).sqlx_logging(false);
            runtime.block_on(Database::connect(opts)).unwrap()
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
