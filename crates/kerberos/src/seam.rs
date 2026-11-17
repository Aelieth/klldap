use krb5_kdc::host::{
    Caller, Denial, HostChange, HostPrepared, KerberosStore, KerberosStoreError, LoadedPrincipal,
    LoadedRealm, Operation, PolicyRow, PrincipalRow, RealmBatch, RealmState, RowChange, TargetPeek,
    WriteIntent,
};
use krb5_kdc::kadm5_mask;
use lldap_domain::types::UserId;
use lldap_domain_handlers::kerberos::{self as directory, DIRECTORY_USER, HostRow};
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_opaque_handler::{OpaqueHandler, prepare_registration};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::warn;
use zeroize::Zeroizing;

// krb5-admin's kadm5 codes (kadm5/codes.rs), which that crate does not export.
pub(crate) const KADM5_PROTECT_PRINCIPAL: u32 = 43_787_550;
pub(crate) const KADM5_PASS_Q_TOOSHORT: u32 = 43_787_542;
pub(crate) const KADM5_AUTH_ADD: u32 = 43_787_522;
pub(crate) const PASSWORD_FLOOR: usize = 8;
const DERIVE_WAIT: Duration = Duration::from_secs(30);

/// What derives a kadmin `cpw`'s OPAQUE record: the server's handler, on the server's runtime.
#[derive(Clone)]
pub struct Records {
    pub handler: Arc<dyn OpaqueHandler>,
    pub runtime: tokio::runtime::Handle,
}

impl Records {
    fn derive(&self, user: &UserId, password: &[u8]) -> Result<Vec<u8>, KerberosStoreError> {
        let (handler, user) = (Arc::clone(&self.handler), user.clone());
        let password = Zeroizing::new(password.to_vec());
        let task = self.runtime.spawn(async move {
            let derived = prepare_registration(&*handler, user, password.as_slice());
            tokio::time::timeout(DERIVE_WAIT, derived).await
        });
        let failed = |why: String| {
            KerberosStoreError::Failed(format!("the password record was not derived: {why}"))
        };
        match self.runtime.block_on(task) {
            Ok(Ok(Ok((record, _)))) => Ok(record),
            Ok(Ok(Err(e))) => Err(failed(e.to_string())),
            Ok(Err(_)) => Err(failed(format!("no answer within {DERIVE_WAIT:?}"))),
            Err(e) => Err(failed(e.to_string())),
        }
    }
}

/// kerber-rust's host store over the directory's database: its rows, in our types.
pub(crate) struct SqlRealm {
    store: Arc<dyn directory::KerberosStore>,
    started: AtomicBool,
    realm: String,
    records: Option<Records>,
}

impl SqlRealm {
    pub(crate) fn new(store: Arc<dyn directory::KerberosStore>) -> Self {
        Self {
            store,
            started: AtomicBool::new(false),
            realm: String::new(),
            records: None,
        }
    }

    /// The realm whose one-part names are the directory's, and what derives a `cpw`'s record.
    pub(crate) fn serving(mut self, realm: &str, records: Option<Records>) -> Self {
        self.realm = realm.to_owned();
        self.records = records;
        self
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

/// A principal name the engine answers for, and the directory user it is or would be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Named {
    pub(crate) principal: String,
    pub(crate) user: Option<UserId>,
}

impl Named {
    pub(crate) fn of(principal: &str, realm: &str) -> Self {
        Self {
            principal: principal.to_owned(),
            user: directory_name(principal, realm),
        }
    }
}

/// One component in our realm, lowercased as the directory stores user ids.
pub(crate) fn directory_name(principal: &str, realm: &str) -> Option<UserId> {
    let (components, in_realm) = krb5_types::parse_name(principal, realm).ok()?;
    match components.as_slice() {
        [one] if !one.is_empty() && !realm.is_empty() && in_realm == realm => {
            Some(UserId::new(one))
        }
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// MIT's write; none of `new` may be a directory user's name.
    Write {
        new: Vec<Named>,
    },
    Unlock(Named),
    Password(Named),
    Deny {
        code: u32,
        named: Named,
    },
}

/// `commit_change`'s answer from the rows, which are the authority (contract rule 4).
pub(crate) fn verdict(change: &HostChange, realm: &str) -> Result<Verdict, KerberosStoreError> {
    let intent = &change.intent;
    match intent.operation {
        Operation::Embedded => {
            return Err(KerberosStoreError::Refused(
                "an own write arrived as another's".to_owned(),
            ));
        }
        Operation::Bootstrap => return Ok(Verdict::Write { new: Vec::new() }),
        _ => {}
    }
    let owned: Vec<&RowChange> = change.rows.iter().filter(|row| row.host_owned).collect();
    let existing = owned.iter().find(|row| row.before.is_some());
    let Some(row) = existing.or_else(|| owned.first()) else {
        let new = change
            .rows
            .iter()
            .filter(|row| row.before.is_none() && row.after.is_some())
            .map(|row| Named::of(&row.id, realm))
            .filter(|named| named.user.is_some())
            .collect();
        return Ok(Verdict::Write { new });
    };
    let named = Named::of(&row.id, realm);
    match intent.operation {
        Operation::Unspecified => Err(KerberosStoreError::Refused(format!(
            "an undeclared write to a directory user's principal: {}",
            row.id
        ))),
        Operation::Modify if owned.len() == 1 && unlock_only(intent) => Ok(Verdict::Unlock(named)),
        Operation::ChangePassword if owned.len() == 1 => Ok(password_verdict(intent, named)),
        _ => Ok(Verdict::Deny {
            code: KADM5_PROTECT_PRINCIPAL,
            named,
        }),
    }
}

/// `prepare`'s answer from the peek; `commit_change` gives it again from the rows.
pub(crate) fn early(intent: &WriteIntent, target: Option<&TargetPeek>, realm: &str) -> Verdict {
    let new = |at: Option<usize>| Verdict::Write {
        new: at
            .and_then(|at| intent.requested.get(at))
            .map(|name| Named::of(name, realm))
            .filter(|named| named.user.is_some())
            .into_iter()
            .collect(),
    };
    let owned = target
        .filter(|peek| peek.host_owned)
        .map(|peek| Named::of(&peek.id, realm));
    match (intent.operation, target, owned) {
        (Operation::Bootstrap | Operation::Embedded | Operation::Unspecified, _, _)
        | (Operation::Create, Some(_), _) => new(None),
        (Operation::Create, None, _) => new(Some(0)),
        (Operation::ChangePassword, _, Some(named)) => password_verdict(intent, named),
        (Operation::Modify, _, Some(named)) if unlock_only(intent) => Verdict::Unlock(named),
        (_, _, Some(named)) => Verdict::Deny {
            code: KADM5_PROTECT_PRINCIPAL,
            named,
        },
        (Operation::Rename, Some(_), None) => new(Some(1)),
        (Operation::CreateAlias, _, None) => new(Some(0)),
        _ => new(None),
    }
}

fn unlock_only(intent: &WriteIntent) -> bool {
    intent.client_mask == Some(kadm5_mask::FAIL_AUTH_COUNT)
}

fn password_verdict(intent: &WriteIntent, named: Named) -> Verdict {
    let keepold = intent.keepold.is_some_and(|keepold| keepold != 0);
    let code = match &intent.password {
        _ if keepold || named.user.is_none() => KADM5_PROTECT_PRINCIPAL,
        Some(password) if long_enough(password.as_slice()) => return Verdict::Password(named),
        Some(_) => KADM5_PASS_Q_TOOSHORT,
        None => KADM5_PROTECT_PRINCIPAL,
    };
    Verdict::Deny { code, named }
}

fn long_enough(password: &[u8]) -> bool {
    let chars = std::str::from_utf8(password).map_or(password.len(), |text| text.chars().count());
    chars >= PASSWORD_FLOOR
}

fn client(caller: &Caller) -> &str {
    match caller {
        Caller::Kadmind { client, .. } | Caller::Kpasswd { client, .. } => client.as_str(),
        Caller::Local { principal } => principal.as_str(),
        Caller::Embedder => "the server",
    }
}

fn self_service(caller: &Caller) -> bool {
    matches!(
        caller,
        Caller::Kadmind {
            self_service: true,
            ..
        } | Caller::Kpasswd {
            self_service: true,
            ..
        }
    )
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Delete => "delete",
        Operation::Rename => "rename",
        Operation::Modify => "modify",
        Operation::ChangePassword => "change_password",
        Operation::Randkey => "randkey",
        Operation::SetKey => "set_key",
        Operation::PurgeKeys => "purge_keys",
        Operation::SetString => "set_string",
        Operation::CreateAlias => "create_alias",
        Operation::CreatePolicy => "create_policy",
        Operation::ModifyPolicy => "modify_policy",
        Operation::DeletePolicy => "delete_policy",
        Operation::Bootstrap => "bootstrap",
        Operation::Embedded => "embedded",
        Operation::Unspecified => "unspecified",
    }
}

pub(crate) fn code_name(code: u32) -> &'static str {
    match code {
        KADM5_PROTECT_PRINCIPAL => "PROTECT_PRINCIPAL",
        KADM5_AUTH_ADD => "AUTH_ADD",
        KADM5_PASS_Q_TOOSHORT => "PASS_Q_TOOSHORT",
        _ => "another code",
    }
}

fn denied(intent: &WriteIntent, code: u32, named: &Named) -> KerberosStoreError {
    let detail = format!(
        "kadmin {} on {} by {}: {}",
        operation_name(intent.operation),
        named.principal,
        client(&intent.caller),
        code_name(code)
    );
    logging::record_failure(LogKind::AccessDenied, Some(&named.principal), &detail);
    let text = match code {
        KADM5_PASS_Q_TOOSHORT => {
            format!("the password is shorter than {PASSWORD_FLOOR} characters")
        }
        KADM5_AUTH_ADD => format!(
            "{} is a directory user's name; turn on Kerberos for the user in KLLDAP",
            named.principal
        ),
        _ => format!(
            "{} belongs to a directory user; change it in KLLDAP",
            named.principal
        ),
    };
    KerberosStoreError::Denied(Denial {
        kadm5_code: code,
        text,
    })
}

struct PreparedRecord {
    user: UserId,
    record: Vec<u8>,
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
        match verdict(&change, &self.realm)? {
            Verdict::Write { new } => self.write_new(change, &new),
            Verdict::Unlock(named) => {
                self.write(Vec::new(), change.batch)?;
                let detail = format!(
                    "kadmin unlock by {} (no lockout counter yet)",
                    client(&change.intent.caller)
                );
                logging::record(LogKind::KerberosSync, Some(&named.principal), Some(&detail));
                Ok(())
            }
            Verdict::Password(named) => self.commit_password(change, &named),
            Verdict::Deny { code, named } => Err(denied(&change.intent, code, &named)),
        }
    }

    fn prepare(
        &self,
        intent: &WriteIntent,
        target: Option<&TargetPeek>,
    ) -> Result<Option<HostPrepared>, KerberosStoreError> {
        if !self.started.load(Ordering::Acquire) {
            return Ok(None);
        }
        match early(intent, target, &self.realm) {
            Verdict::Write { new } => self.read_new(intent, &new).map(|()| None),
            Verdict::Unlock(_) => Ok(None),
            Verdict::Password(named) => self.prepared(intent, &named).map(Some),
            Verdict::Deny { code, named } => Err(denied(intent, code, &named)),
        }
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
    fn records(&self) -> Result<&Records, KerberosStoreError> {
        self.records.as_ref().ok_or_else(|| {
            KerberosStoreError::Refused("no password records are wired to this realm".to_owned())
        })
    }

    fn read_new(&self, intent: &WriteIntent, new: &[Named]) -> Result<(), KerberosStoreError> {
        let users: Vec<UserId> = new.iter().filter_map(|named| named.user.clone()).collect();
        if users.is_empty() {
            return Ok(());
        }
        match self.store.directory_users(&users) {
            Ok(found) => match new
                .iter()
                .find(|named| named.user.as_ref().is_some_and(|u| found.contains(u)))
            {
                Some(named) => Err(denied(intent, KADM5_AUTH_ADD, named)),
                None => Ok(()),
            },
            Err(e) => {
                warn!(
                    "The directory could not be read before a kadmin write; its commit decides: {e}"
                );
                Ok(())
            }
        }
    }

    fn prepared(
        &self,
        intent: &WriteIntent,
        named: &Named,
    ) -> Result<HostPrepared, KerberosStoreError> {
        let (Some(user), Some(password)) = (&named.user, &intent.password) else {
            return Err(denied(intent, KADM5_PROTECT_PRINCIPAL, named));
        };
        let record = self.records()?.derive(user, password.as_slice())?;
        Ok(Box::new(PreparedRecord {
            user: user.clone(),
            record,
        }))
    }

    fn write_new(&self, change: HostChange, new: &[Named]) -> Result<(), KerberosStoreError> {
        let users: Vec<UserId> = new.iter().filter_map(|named| named.user.clone()).collect();
        let rows = if users.is_empty() {
            Vec::new()
        } else {
            vec![HostRow::NoUser(users)]
        };
        match self.write(rows, change.batch) {
            Err(KerberosStoreError::Refused(why)) if why == DIRECTORY_USER => {
                let named = match new {
                    [one] => one.clone(),
                    _ => Named {
                        principal: new
                            .iter()
                            .map(|named| named.principal.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                        user: None,
                    },
                };
                Err(denied(&change.intent, KADM5_AUTH_ADD, &named))
            }
            written => written,
        }
    }

    fn commit_password(&self, change: HostChange, named: &Named) -> Result<(), KerberosStoreError> {
        let HostChange {
            intent,
            prepared,
            batch,
            ..
        } = change;
        let (Some(user), Some(password)) = (named.user.clone(), &intent.password) else {
            return Err(denied(&intent, KADM5_PROTECT_PRINCIPAL, named));
        };
        let record = match prepared.and_then(|p| p.downcast::<PreparedRecord>().ok()) {
            Some(p) if p.user == user => p.record,
            _ => {
                warn!(
                    "kadmin change_password for {user}: deriving the record under the store's lock"
                );
                self.records()?.derive(&user, password.as_slice())?
            }
        };
        let mut detail = format!("kadmin change_password by {}", client(&intent.caller));
        if self_service(&intent.caller) {
            detail.push_str(" (self-service)");
        }
        let row = logging::event(
            LogKind::PasswordChange,
            Some(&named.principal),
            true,
            Some(&detail),
        );
        let rows = vec![
            HostRow::SetPassword {
                user,
                record,
                now: chrono::Utc::now().naive_utc(),
            },
            HostRow::Log(row.clone()),
        ];
        self.write(rows, batch)?;
        logging::print(&row);
        Ok(())
    }

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

    const ADMIN: &str = "admin/admin@EXAMPLE.COM";

    type Fill = Box<dyn Fn(&mut WriteIntent)>;
    type Edit<'a> = Box<dyn Fn(&mut krb5_kdc::PrincipalStore) -> Result<(), StoreError> + 'a>;
    type Case<'a> = (
        &'static str,
        Operation,
        &'static [&'static str],
        Fill,
        Edit<'a>,
        &'static str,
    );

    fn name(text: &str) -> PrincipalName {
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, text.split('/'))
    }

    fn kadmin(self_service: bool) -> Caller {
        let client = if self_service {
            "bob@EXAMPLE.COM"
        } else {
            ADMIN
        };
        Caller::Kadmind {
            client: client.to_owned(),
            initial: self_service,
            changepw_service: false,
            self_service,
        }
    }

    fn nothing() -> Fill {
        Box::new(|_: &mut WriteIntent| {})
    }

    fn mask(bits: u32) -> Fill {
        Box::new(move |intent: &mut WriteIntent| intent.client_mask = Some(bits))
    }

    fn with_password(text: &'static str, keepold: u32) -> Fill {
        Box::new(move |intent: &mut WriteIntent| {
            intent.password = Some(Zeroizing::new(text.as_bytes().to_vec()));
            intent.keepold = Some(keepold);
        })
    }

    fn intent_of(
        operation: Operation,
        caller: Caller,
        requested: &[&str],
        fill: &dyn Fn(&mut WriteIntent),
    ) -> WriteIntent {
        let mut intent = WriteIntent::new(operation, caller);
        intent.requested = requested
            .iter()
            .map(|name| format!("{name}@EXAMPLE.COM"))
            .collect();
        fill(&mut intent);
        intent
    }

    fn kadmin_try(
        store: &krb5_kdc::SharedDump,
        declared: bool,
        intent: WriteIntent,
        peek: &PrincipalName,
        edit: &dyn Fn(&mut krb5_kdc::PrincipalStore) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let (intent, prepared) = if declared {
            krb5_kdc::declare_shared(store, Some((peek, "EXAMPLE.COM")), |_| intent)?
        } else {
            (intent, None)
        };
        store
            .write()
            .unwrap()
            .change_as(intent, prepared, |s| edit(s))?
    }

    /// kadmind's write below the RPC: the peek and `prepare` when `declared`, then the commit.
    fn kadmin_write(
        store: &krb5_kdc::SharedDump,
        declared: bool,
        intent: WriteIntent,
        peek: &PrincipalName,
        edit: &dyn Fn(&mut krb5_kdc::PrincipalStore) -> Result<(), StoreError>,
    ) -> String {
        match kadmin_try(store, declared, intent, peek, edit) {
            Ok(()) => "written".to_owned(),
            Err(StoreError::Host(KerberosStoreError::Denied(denial))) => {
                code_name(denial.kadm5_code).to_owned()
            }
            Err(e) => e.to_string(),
        }
    }

    fn details(pool: &DatabaseConnection, runtime: &Runtime, kind: &str) -> Vec<String> {
        let query = format!("SELECT detail FROM logs WHERE kind = '{kind}' ORDER BY id");
        let statement = sea_orm::Statement::from_string(pool.get_database_backend(), query);
        runtime
            .block_on(pool.query_all(statement))
            .unwrap()
            .iter()
            .map(|row| row.try_get::<String>("", "detail").unwrap())
            .collect()
    }

    type Rows = Vec<(LogKind, Option<String>, Option<String>)>;

    fn denial(principal: &str, operation: &str, code: &str) -> Rows {
        let detail = format!("kadmin {operation} on {principal} by {ADMIN}: {code}");
        vec![(
            LogKind::AccessDenied,
            Some(principal.to_owned()),
            Some(detail),
        )]
    }

    // K1: kadmind's declared writes on a directory user's principal and names, on one database.
    fn kadmin_rows_on(connect: Reconnect) {
        use krb5_kdc::{AdminFields, KeyEntry, PrincipalStore};
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain_handlers::handler::{BindRequest, LoginHandler};
        use lldap_sql_backend_handler::SqlBackendHandler;
        use lldap_test_utils::recording_log::LogGuard;

        let guard = LogGuard::install();
        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let (committer, pool) = committer_on(connect, &runtime);
        for user in ["bob", "alice"] {
            add_user(&pool, &runtime, user);
        }
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let records = Records {
            handler: Arc::new(handler.clone()),
            runtime: runtime.handle().clone(),
        };
        let host = Arc::new(SqlRealm::new(committer.store()).serving("EXAMPLE.COM", Some(records)));
        host.start_pass_committed();
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        runtime
            .block_on(embedded.sync_principal(&UserId::new("bob"), "Bob-Password-1"))
            .unwrap();
        let (bob, svc, robert) = (name("bob"), name("HTTP/web.example.com"), name("robert"));
        let (alice, twin, web, moved) = (
            name("alice"),
            name("Alice"),
            name("web"),
            name("HTTP/new.example.com"),
        );
        store
            .write()
            .unwrap()
            .change_committing(committing(&*host), |s| {
                s.insert_new_randkey(&svc, "EXAMPLE.COM", &[], "test")
            })
            .unwrap()
            .unwrap();
        let etypes: Vec<krb5_crypto::KeySalt> = temp
            .settings
            .supported_enctypes
            .iter()
            .map(|&e| e.into())
            .collect();
        let keys = || {
            let etype = krb5_crypto::EncryptionType::Aes256CtsHmacSha196;
            let key = krb5_kdc::random_key(etype).unwrap();
            vec![KeyEntry {
                etype,
                key,
                kvno: 0,
                salt_type: None,
                kdb_salt: None,
            }]
        };
        let fields = || AdminFields {
            max_life: Some(3600),
            ..Default::default()
        };
        let record = || host.password_record(&UserId::new("bob")).unwrap();
        let kvno = |n: &PrincipalName| store.read().unwrap().get_name(n).and_then(|p| p.top_kvno());
        let binds = |password: &str| {
            let request = BindRequest {
                name: UserId::new("bob"),
                password: password.to_owned(),
            };
            runtime.block_on(handler.bind(request)).is_ok()
        };
        let rows = || -> Rows {
            let events = guard.recorder().take_events().into_iter();
            events
                .filter(|e| e.kind != LogKind::Bind)
                .map(|e| (e.kind, e.target, e.detail))
                .collect()
        };
        rows();

        let held = (host.load().unwrap(), record());
        let on_bob: [Case; 11] = [
            (
                "randkey",
                Operation::Randkey,
                &["bob"],
                nothing(),
                Box::new(|s: &mut PrincipalStore| {
                    s.chrand_etypes_keepold_in(&bob, "EXAMPLE.COM", &etypes, 0, ADMIN)
                        .map(drop)
                }),
                "randkey: PROTECT_PRINCIPAL",
            ),
            (
                "setkey",
                Operation::SetKey,
                &["bob"],
                nothing(),
                Box::new(|s: &mut PrincipalStore| {
                    s.set_keys_in(&bob, "EXAMPLE.COM", keys(), 0, ADMIN)
                }),
                "set_key: PROTECT_PRINCIPAL",
            ),
            (
                "purgekeys",
                Operation::PurgeKeys,
                &["bob"],
                nothing(),
                Box::new(|s: &mut PrincipalStore| s.purgekeys_in(&bob, "EXAMPLE.COM", 0, ADMIN)),
                "purge_keys: PROTECT_PRINCIPAL",
            ),
            (
                "modify",
                Operation::Modify,
                &["bob"],
                mask(kadm5_mask::MAX_LIFE),
                Box::new(|s: &mut PrincipalStore| {
                    s.apply_admin_fields_in(&bob, "EXAMPLE.COM", fields(), ADMIN)
                }),
                "modify: PROTECT_PRINCIPAL",
            ),
            (
                "unlock with another field",
                Operation::Modify,
                &["bob"],
                mask(kadm5_mask::FAIL_AUTH_COUNT | kadm5_mask::MAX_LIFE),
                Box::new(|s: &mut PrincipalStore| {
                    s.apply_admin_fields_in(&bob, "EXAMPLE.COM", fields(), ADMIN)
                }),
                "modify: PROTECT_PRINCIPAL",
            ),
            (
                "setstring",
                Operation::SetString,
                &["bob"],
                nothing(),
                Box::new(|s: &mut PrincipalStore| {
                    s.set_string_in(&bob, "EXAMPLE.COM", "note", Some("kadmin"), ADMIN)
                }),
                "set_string: PROTECT_PRINCIPAL",
            ),
            (
                "delete",
                Operation::Delete,
                &["bob"],
                nothing(),
                Box::new(|s: &mut PrincipalStore| s.remove_in(&bob, "EXAMPLE.COM")),
                "delete: PROTECT_PRINCIPAL",
            ),
            (
                "rename away",
                Operation::Rename,
                &["bob", "robert"],
                nothing(),
                Box::new(|s: &mut PrincipalStore| {
                    s.rename_unchecked(&bob, "EXAMPLE.COM", &robert, "EXAMPLE.COM", ADMIN)
                }),
                "rename: PROTECT_PRINCIPAL",
            ),
            (
                "cpw -keepold",
                Operation::ChangePassword,
                &["bob"],
                with_password("Bob-Password-9", 1),
                Box::new(|s: &mut PrincipalStore| {
                    let password = b"Bob-Password-9";
                    s.set_password_etypes_keepold_n_in(
                        &bob,
                        "EXAMPLE.COM",
                        password,
                        1,
                        ADMIN,
                        &etypes,
                    )
                }),
                "change_password: PROTECT_PRINCIPAL",
            ),
            (
                "cpw of 7 characters",
                Operation::ChangePassword,
                &["bob"],
                with_password("Short-7", 0),
                Box::new(|s: &mut PrincipalStore| {
                    let password = b"Short-7";
                    s.set_password_etypes_keepold_n_in(
                        &bob,
                        "EXAMPLE.COM",
                        password,
                        0,
                        ADMIN,
                        &etypes,
                    )
                }),
                "change_password: PASS_Q_TOOSHORT",
            ),
            (
                "alias onto bob",
                Operation::CreateAlias,
                &["robert", "bob"],
                nothing(),
                Box::new(|s: &mut PrincipalStore| {
                    s.create_alias_in(&robert, "EXAMPLE.COM", &bob, "EXAMPLE.COM", ADMIN)
                }),
                "create_alias: PROTECT_PRINCIPAL",
            ),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (label, operation, requested, fill, edit, row) in &on_bob {
            let (op, code) = row.split_once(": ").unwrap();
            for declared in [true, false] {
                // The commit's rows carry the alias, not its target: only `prepare` sees the mark.
                if !declared && *operation == Operation::CreateAlias {
                    continue;
                }
                let intent = intent_of(*operation, kadmin(false), requested, fill);
                let answer = kadmin_write(&store, declared, intent, &bob, &**edit);
                let unchanged = (host.load().unwrap(), record()) == held;
                got.push((*label, declared, answer, unchanged, rows()));
                let logged = denial("bob@EXAMPLE.COM", op, code);
                want.push((*label, declared, code.to_owned(), true, logged));
            }
        }
        assert_eq!(got, want, "refused on a directory user's principal");

        let names: [(Case, &PrincipalName, &str); 6] = [
            (
                (
                    "create",
                    Operation::Create,
                    &["alice"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.insert_new_randkey(&alice, "EXAMPLE.COM", &[], ADMIN)
                    }),
                    "create",
                ),
                &alice,
                "alice@EXAMPLE.COM",
            ),
            (
                (
                    "create a case twin",
                    Operation::Create,
                    &["Alice"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.insert_new_randkey(&twin, "EXAMPLE.COM", &[], ADMIN)
                    }),
                    "create",
                ),
                &twin,
                "Alice@EXAMPLE.COM",
            ),
            (
                (
                    "rename onto",
                    Operation::Rename,
                    &["HTTP/web.example.com", "alice"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.rename_unchecked(&svc, "EXAMPLE.COM", &alice, "EXAMPLE.COM", ADMIN)
                    }),
                    "rename",
                ),
                &svc,
                "alice@EXAMPLE.COM",
            ),
            (
                (
                    "rename onto a case twin",
                    Operation::Rename,
                    &["HTTP/web.example.com", "Alice"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.rename_unchecked(&svc, "EXAMPLE.COM", &twin, "EXAMPLE.COM", ADMIN)
                    }),
                    "rename",
                ),
                &svc,
                "Alice@EXAMPLE.COM",
            ),
            (
                (
                    "alias named as the user",
                    Operation::CreateAlias,
                    &["alice", "HTTP/web.example.com"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.create_alias_in(&alice, "EXAMPLE.COM", &svc, "EXAMPLE.COM", ADMIN)
                    }),
                    "create_alias",
                ),
                &svc,
                "alice@EXAMPLE.COM",
            ),
            (
                (
                    "alias named as a case twin",
                    Operation::CreateAlias,
                    &["Alice", "HTTP/web.example.com"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.create_alias_in(&twin, "EXAMPLE.COM", &svc, "EXAMPLE.COM", ADMIN)
                    }),
                    "create_alias",
                ),
                &svc,
                "Alice@EXAMPLE.COM",
            ),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for ((label, operation, requested, fill, edit, op), peek, principal) in &names {
            for declared in [true, false] {
                let intent = intent_of(*operation, kadmin(false), requested, fill);
                let answer = kadmin_write(&store, declared, intent, peek, &**edit);
                let unchanged = (host.load().unwrap(), record()) == held;
                got.push((*label, declared, answer, unchanged, rows()));
                let logged = denial(principal, op, "AUTH_ADD");
                want.push((*label, declared, "AUTH_ADD".to_owned(), true, logged));
            }
        }
        assert_eq!(got, want, "a directory user's name, created");

        let dup = intent_of(Operation::Create, kadmin(false), &["bob"], &nothing());
        let peek = TargetPeek {
            id: "bob@EXAMPLE.COM".to_owned(),
            host_owned: true,
        };
        let answered = host
            .prepare(&dup, Some(&peek))
            .map(|prepared| prepared.is_none());
        let declared = krb5_kdc::declare_shared(&store, Some((&bob, "EXAMPLE.COM")), |_| dup);
        assert_eq!(
            (answered, matches!(declared, Ok((_, None))), rows()),
            (Ok(true), true, Vec::new()),
            "a create of an existing name is left to kadmind's DUP"
        );

        let cpw = |caller: Caller, text: &'static str, declared: bool| {
            let fill = with_password(text, 0);
            let intent = intent_of(Operation::ChangePassword, caller, &["bob"], &fill);
            let edit = |s: &mut PrincipalStore| {
                let password = text.as_bytes();
                s.set_password_etypes_keepold_n_in(&bob, "EXAMPLE.COM", password, 0, ADMIN, &etypes)
            };
            kadmin_write(&store, declared, intent, &bob, &edit)
        };
        let carried = [
            ("an admin's cpw", kadmin(false), "Bob-Password-2", true),
            ("a self-service cpw", kadmin(true), "Bob-Password-3", true),
            (
                "a cpw kadmind did not prepare",
                kadmin(false),
                "Bob-Password-4",
                false,
            ),
        ];
        let mut got = Vec::new();
        for (label, caller, text, declared) in carried {
            let (before, stored) = (kvno(&bob), record());
            let answer = cpw(caller, text, declared);
            let both = (kvno(&bob) == before.map(|k| k + 1), record() != stored);
            got.push((label, answer, both, binds(text), rows()));
        }
        let by_admin = format!("kadmin change_password by {ADMIN}");
        let by_bob = "kadmin change_password by bob@EXAMPLE.COM (self-service)".to_owned();
        let done = |label| (label, "written".to_owned(), (true, true), true, Vec::new());
        assert_eq!(
            (got, details(&pool, &runtime, "password_change")),
            (
                vec![
                    done("an admin's cpw"),
                    done("a self-service cpw"),
                    done("a cpw kadmind did not prepare"),
                ],
                vec![by_admin.clone(), by_bob, by_admin],
            ),
            "carried out: the keys, the record and one row"
        );

        let unlock = intent_of(
            Operation::Modify,
            kadmin(false),
            &["bob"],
            &mask(kadm5_mask::FAIL_AUTH_COUNT),
        );
        let edit = |s: &mut PrincipalStore| s.clear_fail_auth_count_in(&bob, "EXAMPLE.COM", ADMIN);
        let unlocked = kadmin_write(&store, true, unlock, &bob, &edit);
        let unlock_row = format!("kadmin unlock by {ADMIN} (no lockout counter yet)");
        assert_eq!(
            (unlocked, rows()),
            (
                "written".to_owned(),
                vec![(
                    LogKind::KerberosSync,
                    Some("bob@EXAMPLE.COM".to_owned()),
                    Some(unlock_row)
                )]
            )
        );

        let stored = record();
        let control: [(Case, &PrincipalName); 11] = [
            (
                (
                    "randkey",
                    Operation::Randkey,
                    &["HTTP/web.example.com"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.chrand_etypes_keepold_in(&svc, "EXAMPLE.COM", &etypes, 0, ADMIN)
                            .map(drop)
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "setkey",
                    Operation::SetKey,
                    &["HTTP/web.example.com"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.set_keys_in(&svc, "EXAMPLE.COM", keys(), 0, ADMIN)
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "purgekeys",
                    Operation::PurgeKeys,
                    &["HTTP/web.example.com"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.purgekeys_in(&svc, "EXAMPLE.COM", 0, ADMIN)
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "modify",
                    Operation::Modify,
                    &["HTTP/web.example.com"],
                    mask(kadm5_mask::MAX_LIFE),
                    Box::new(|s: &mut PrincipalStore| {
                        s.apply_admin_fields_in(&svc, "EXAMPLE.COM", fields(), ADMIN)
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "unlock",
                    Operation::Modify,
                    &["HTTP/web.example.com"],
                    mask(kadm5_mask::FAIL_AUTH_COUNT),
                    Box::new(|s: &mut PrincipalStore| {
                        s.clear_fail_auth_count_in(&svc, "EXAMPLE.COM", ADMIN)
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "setstring",
                    Operation::SetString,
                    &["HTTP/web.example.com"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.set_string_in(&svc, "EXAMPLE.COM", "note", Some("kadmin"), ADMIN)
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "cpw of 7 characters",
                    Operation::ChangePassword,
                    &["HTTP/web.example.com"],
                    with_password("Short-7", 0),
                    Box::new(|s: &mut PrincipalStore| {
                        let password = b"Short-7";
                        s.set_password_etypes_keepold_n_in(
                            &svc,
                            "EXAMPLE.COM",
                            password,
                            0,
                            ADMIN,
                            &etypes,
                        )
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "cpw -keepold",
                    Operation::ChangePassword,
                    &["HTTP/web.example.com"],
                    with_password("Svc-Password-1", 1),
                    Box::new(|s: &mut PrincipalStore| {
                        let password = b"Svc-Password-1";
                        s.set_password_etypes_keepold_n_in(
                            &svc,
                            "EXAMPLE.COM",
                            password,
                            1,
                            ADMIN,
                            &etypes,
                        )
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "alias",
                    Operation::CreateAlias,
                    &["web", "HTTP/web.example.com"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.create_alias_in(&web, "EXAMPLE.COM", &svc, "EXAMPLE.COM", ADMIN)
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "rename",
                    Operation::Rename,
                    &["HTTP/web.example.com", "HTTP/new.example.com"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.rename_unchecked(&svc, "EXAMPLE.COM", &moved, "EXAMPLE.COM", ADMIN)
                    }),
                    "",
                ),
                &svc,
            ),
            (
                (
                    "delete",
                    Operation::Delete,
                    &["HTTP/new.example.com"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| s.remove_in(&moved, "EXAMPLE.COM")),
                    "",
                ),
                &moved,
            ),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for ((label, operation, requested, fill, edit, _), peek) in &control {
            let intent = intent_of(*operation, kadmin(false), requested, fill);
            let answer = kadmin_write(&store, true, intent, peek, &**edit);
            got.push((*label, answer, rows()));
            want.push((*label, "written".to_owned(), Vec::new()));
        }
        assert_eq!(
            (got, record() == stored),
            (want, true),
            "a service principal: MIT's"
        );

        sql(
            &pool,
            &runtime,
            "UPDATE kerberos_realm SET generation = generation + 1",
        );
        let (before, stored) = (kvno(&bob), record());
        let lost = cpw(kadmin(false), "Bob-Password-5", true);
        assert_eq!(
            (
                lost == "written",
                kvno(&bob) == before,
                record() == stored,
                binds("Bob-Password-4"),
                details(&pool, &runtime, "password_change").len(),
                rows()
            ),
            (false, true, true, true, 3, Vec::new()),
            "the realm was lost before the commit: nothing written, {lost}"
        );
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_kadmin_writes_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-k1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("k1.db").display());
        kadmin_rows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_the_verdict_on_each_intent() {
        type Row = (Operation, bool, fn(&mut WriteIntent), &'static str);
        fn password(intent: &mut WriteIntent, text: &str, keepold: u32) {
            intent.password = Some(Zeroizing::new(text.as_bytes().to_vec()));
            intent.keepold = Some(keepold);
        }
        let rows: [Row; 13] = [
            (Operation::Unspecified, false, |_| {}, "written"),
            (Operation::Modify, false, |_| {}, "written"),
            (Operation::Embedded, false, |_| {}, "refused"),
            (Operation::Bootstrap, true, |_| {}, "written"),
            (Operation::Unspecified, true, |_| {}, "refused"),
            (Operation::Modify, true, |_| {}, "PROTECT_PRINCIPAL"),
            (Operation::ChangePassword, true, |_| {}, "PROTECT_PRINCIPAL"),
            (Operation::Embedded, true, |_| {}, "refused"),
            (
                Operation::Modify,
                true,
                |i| i.client_mask = Some(kadm5_mask::FAIL_AUTH_COUNT),
                "unlock bob@EXAMPLE.COM",
            ),
            (
                Operation::Modify,
                true,
                |i| i.client_mask = Some(kadm5_mask::FAIL_AUTH_COUNT | kadm5_mask::MAX_LIFE),
                "PROTECT_PRINCIPAL",
            ),
            (
                Operation::ChangePassword,
                true,
                |i| password(i, "Bob-Pass-9", 0),
                "password bob@EXAMPLE.COM",
            ),
            (
                Operation::ChangePassword,
                true,
                |i| password(i, "Bob-Pass-9", 1),
                "PROTECT_PRINCIPAL",
            ),
            (
                Operation::ChangePassword,
                true,
                |i| password(i, "pässwör", 0),
                "PASS_Q_TOOSHORT",
            ),
        ];
        for (operation, owned, fill, expected) in rows {
            let mut intent = WriteIntent::new(operation, Caller::Embedder);
            fill(&mut intent);
            let change = HostChange {
                intent,
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
            let got = match verdict(&change, "EXAMPLE.COM") {
                Ok(Verdict::Write { new }) if new.is_empty() => "written".to_owned(),
                Ok(Verdict::Unlock(named)) => format!("unlock {}", named.principal),
                Ok(Verdict::Password(named)) => format!("password {}", named.principal),
                Ok(Verdict::Deny { code, .. }) => code_name(code).to_owned(),
                Err(KerberosStoreError::Refused(_)) => "refused".to_owned(),
                other => format!("{other:?}"),
            };
            assert_eq!(got, expected, "{operation:?}, owned {owned}");
        }
    }

    fn shown(verdict: Verdict) -> String {
        match verdict {
            Verdict::Write { new } if new.is_empty() => "pass".to_owned(),
            Verdict::Write { new } => {
                let names: Vec<_> = new
                    .iter()
                    .map(|n| {
                        format!(
                            "{} as {}",
                            n.principal,
                            n.user.as_ref().map_or("", UserId::as_str)
                        )
                    })
                    .collect();
                format!("ask {}", names.join(", "))
            }
            Verdict::Unlock(named) => format!("unlock {}", named.principal),
            Verdict::Password(named) => format!("password {}", named.principal),
            Verdict::Deny { code, named } => format!("{} {}", code_name(code), named.principal),
        }
    }

    #[test]
    fn test_prepare_answers_from_the_peek() {
        type Row = (
            &'static str,
            Operation,
            Option<(&'static str, bool)>,
            [&'static str; 2],
            fn(&mut WriteIntent),
            &'static str,
        );
        fn password(intent: &mut WriteIntent, text: &str, keepold: u32) {
            intent.password = Some(Zeroizing::new(text.as_bytes().to_vec()));
            intent.keepold = Some(keepold);
        }
        let (bob, svc) = (
            Some(("bob@EXAMPLE.COM", true)),
            Some(("svc@EXAMPLE.COM", false)),
        );
        let rows: [Row; 24] = [
            (
                "create, no record",
                Operation::Create,
                None,
                ["alice@EXAMPLE.COM", ""],
                |_| {},
                "ask alice@EXAMPLE.COM as alice",
            ),
            (
                "create, a case twin",
                Operation::Create,
                None,
                ["Alice@EXAMPLE.COM", ""],
                |_| {},
                "ask Alice@EXAMPLE.COM as alice",
            ),
            (
                "create, a record exists: DUP under the lock",
                Operation::Create,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |_| {},
                "pass",
            ),
            (
                "create, two components",
                Operation::Create,
                None,
                ["alice/admin@EXAMPLE.COM", ""],
                |_| {},
                "pass",
            ),
            (
                "create, another realm",
                Operation::Create,
                None,
                ["alice@OTHER.ORG", ""],
                |_| {},
                "pass",
            ),
            (
                "rename away",
                Operation::Rename,
                bob,
                ["bob@EXAMPLE.COM", "robert@EXAMPLE.COM"],
                |_| {},
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM",
            ),
            (
                "rename onto a user",
                Operation::Rename,
                svc,
                ["svc@EXAMPLE.COM", "Alice@EXAMPLE.COM"],
                |_| {},
                "ask Alice@EXAMPLE.COM as alice",
            ),
            (
                "rename of no record",
                Operation::Rename,
                None,
                ["svc@EXAMPLE.COM", "alice@EXAMPLE.COM"],
                |_| {},
                "pass",
            ),
            (
                "alias onto an owned record",
                Operation::CreateAlias,
                bob,
                ["robert@EXAMPLE.COM", "bob@EXAMPLE.COM"],
                |_| {},
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM",
            ),
            (
                "alias named as a user",
                Operation::CreateAlias,
                svc,
                ["alice@EXAMPLE.COM", "svc@EXAMPLE.COM"],
                |_| {},
                "ask alice@EXAMPLE.COM as alice",
            ),
            (
                "alias named as a case twin, no target",
                Operation::CreateAlias,
                None,
                ["Alice@EXAMPLE.COM", "svc@EXAMPLE.COM"],
                |_| {},
                "ask Alice@EXAMPLE.COM as alice",
            ),
            (
                "cpw",
                Operation::ChangePassword,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |i| password(i, "Bob-Password-2", 0),
                "password bob@EXAMPLE.COM",
            ),
            (
                "cpw of 7 characters in 9 bytes",
                Operation::ChangePassword,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |i| password(i, "pässwör", 0),
                "PASS_Q_TOOSHORT bob@EXAMPLE.COM",
            ),
            (
                "cpw of 8 characters",
                Operation::ChangePassword,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |i| password(i, "pässwörd", 0),
                "password bob@EXAMPLE.COM",
            ),
            (
                "cpw -keepold",
                Operation::ChangePassword,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |i| password(i, "Bob-Password-2", 1),
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM",
            ),
            (
                "cpw of an unowned record",
                Operation::ChangePassword,
                svc,
                ["svc@EXAMPLE.COM", ""],
                |i| password(i, "short", 1),
                "pass",
            ),
            (
                "unlock",
                Operation::Modify,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |i| i.client_mask = Some(kadm5_mask::FAIL_AUTH_COUNT),
                "unlock bob@EXAMPLE.COM",
            ),
            (
                "unlock and more",
                Operation::Modify,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |i| i.client_mask = Some(kadm5_mask::FAIL_AUTH_COUNT | kadm5_mask::MAX_LIFE),
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM",
            ),
            (
                "randkey",
                Operation::Randkey,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |_| {},
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM",
            ),
            (
                "setkey",
                Operation::SetKey,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |_| {},
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM",
            ),
            (
                "purgekeys",
                Operation::PurgeKeys,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |_| {},
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM",
            ),
            (
                "setstring",
                Operation::SetString,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |_| {},
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM",
            ),
            (
                "delete",
                Operation::Delete,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |_| {},
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM",
            ),
            (
                "randkey of an unowned record",
                Operation::Randkey,
                svc,
                ["svc@EXAMPLE.COM", ""],
                |_| {},
                "pass",
            ),
        ];
        for (label, operation, peek, requested, fill, expected) in rows {
            let mut intent = WriteIntent::new(operation, Caller::Embedder);
            intent.requested = requested
                .into_iter()
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect();
            fill(&mut intent);
            let peek = peek.map(|(id, host_owned)| TargetPeek {
                id: id.to_owned(),
                host_owned,
            });
            let got = shown(early(&intent, peek.as_ref(), "EXAMPLE.COM"));
            assert_eq!(got, expected, "{label}");
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
