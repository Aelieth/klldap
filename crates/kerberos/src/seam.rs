use crate::embedded::Follow;
use krb5_kdc::host::{
    Caller, Denial, HostChange, HostPrepared, KerberosStore, KerberosStoreError, LoadedPrincipal,
    LoadedRealm, Operation, PolicyRow, PrincipalRow, RealmBatch, RealmState, RowChange, TargetPeek,
    WriteIntent,
};
use krb5_kdc::{
    MAX_ALIAS_DEPTH, Principal, TL_LAST_ADMIN_UNLOCK, TL_MOD_PRINC, TlData, kadm5_mask,
    lookup_principal_id,
};
use lldap_domain::types::UserId;
use lldap_domain_handlers::handler::PolicyBackendHandler;
use lldap_domain_handlers::kerberos::{
    self as directory, AliasOnto, DIRECTORY_TARGET, DIRECTORY_USER, HostRow,
};
use lldap_domain_handlers::lockout::{UNLOCKED_BY_KADMIN, lock_clock, lockout};
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_domain_handlers::password::{
    PASSWORD_LENGTH_UNIT, PASSWORD_MIN_LENGTH, PASSWORD_POLICY_UNREADABLE, PasswordChangeError,
    min_length_for_user, password_rules,
};
use lldap_domain_handlers::policies::POLICY_READ_WAIT;
use lldap_opaque_handler::{OpaqueHandler, prepare_registration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::warn;
use zeroize::Zeroizing;

// krb5-admin's kadm5 codes (kadm5/codes.rs), which that crate does not export.
pub(crate) const KADM5_PROTECT_PRINCIPAL: u32 = 43_787_550;
pub(crate) const KADM5_PASS_Q_TOOSHORT: u32 = 43_787_542;
pub(crate) const KADM5_AUTH_ADD: u32 = 43_787_522;
pub(crate) const KADM5_PASS_Q_GENERIC: u32 = 43_787_577;
const DERIVE_WAIT: Duration = Duration::from_secs(30);
const UNPREPARED: &str = "the change could not be prepared";
const POLICY_UNREAD: &str = "the password policy could not be read";
const NO_FOLLOW: &str = "after kadmin change_password the status was not set from \
     lldap_disabled and stays as it was: no realm engine is wired to this host";
const UNLOCK_ROW_BITS: u32 = kadm5_mask::TL_DATA | kadm5_mask::MOD_TIME | kadm5_mask::MOD_NAME;

/// What derives a kadmin `cpw`'s OPAQUE record: the server's handler, on the server's runtime.
#[derive(Clone)]
pub struct Records {
    pub handler: Arc<dyn OpaqueHandler>,
    pub policies: Arc<dyn PolicyBackendHandler>,
    pub runtime: tokio::runtime::Handle,
}

/// kadmind's thread waits at most `wait`, whether or not the runtime ever polls the task.
fn answer_within<T: Send + 'static>(
    runtime: &tokio::runtime::Handle,
    wait: Duration,
    work: impl std::future::Future<Output = T> + Send + 'static,
) -> Result<T, String> {
    let (answer, answered) = mpsc::sync_channel(1);
    let task = runtime.spawn(async move {
        let _ = answer.send(work.await);
    });
    let got = answered.recv_timeout(wait);
    task.abort();
    got.map_err(|e| match e {
        RecvTimeoutError::Timeout => format!("no answer within {wait:?}"),
        RecvTimeoutError::Disconnected => "the task ended without an answer".to_owned(),
    })
}

impl Records {
    fn min_length(&self, user: &UserId) -> Result<usize, String> {
        let (policies, user) = (Arc::clone(&self.policies), user.clone());
        let read = async move { min_length_for_user(&*policies, &user).await };
        answer_within(&self.runtime, POLICY_READ_WAIT, read)?.map_err(|e| e.to_string())
    }

    fn hold(
        &self,
        intent: &WriteIntent,
        named: &Named,
        user: &UserId,
        password: &[u8],
    ) -> Result<usize, KerberosStoreError> {
        let min = self.min_length(user).map_err(|why| {
            warn!("kadmin change_password for {user}: {POLICY_UNREAD}: {why}");
            denied(intent, Refusal::PolicyUnread, named)
        })?;
        held_to(intent, named, password, min).map(|()| min)
    }

    fn derive(&self, user: &UserId, password: &[u8]) -> Result<Vec<u8>, KerberosStoreError> {
        let (handler, user) = (Arc::clone(&self.handler), user.clone());
        let password = Zeroizing::new(password.to_vec());
        let derived =
            async move { prepare_registration(&*handler, user, password.as_slice()).await };
        let failed = |why: String| {
            KerberosStoreError::Failed(format!("the password record was not derived: {why}"))
        };
        match answer_within(&self.runtime, DERIVE_WAIT, derived) {
            Ok(Ok((record, _))) => Ok(record),
            Ok(Err(e)) => Err(failed(e.to_string())),
            Err(why) => Err(failed(why)),
        }
    }
}

/// kerber-rust's host store over the directory's database: its rows, in our types.
pub(crate) struct SqlRealm {
    store: Arc<dyn directory::KerberosStore>,
    started: AtomicBool,
    realm: String,
    records: Option<Records>,
    follow: Mutex<Option<Follow>>,
    following: Arc<AtomicBool>,
}

impl SqlRealm {
    pub(crate) fn new(store: Arc<dyn directory::KerberosStore>) -> Self {
        Self {
            store,
            started: AtomicBool::new(false),
            realm: String::new(),
            records: None,
            follow: Mutex::new(None),
            following: Arc::new(AtomicBool::new(false)),
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
    fn user_disabled(&self, user: &UserId) -> Result<bool, KerberosStoreError>;
    fn user_synced(&self, user: &UserId) -> Result<bool, KerberosStoreError>;
    fn synced_statuses(&self) -> Result<Vec<(UserId, bool)>, KerberosStoreError>;
    fn directory_users(&self, users: &[UserId]) -> Result<Vec<UserId>, KerberosStoreError>;
    /// Until the start pass has committed, only the bootstrap may come from outside.
    fn start_pass_committed(&self);
    fn fill_alias_targets(&self, rows: &[(String, String)]) -> Result<u64, KerberosStoreError>;
    fn follow_with(&self, _follow: Follow) {}
    fn realm_not_held(&self) -> Option<String> {
        None
    }
    fn realm_unsettled(&self) -> Option<String> {
        None
    }
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
    /// The name as sent, when the write reached `principal` through an alias.
    pub(crate) sent: Option<String>,
}

impl Named {
    pub(crate) fn of(principal: &str, realm: &str) -> Self {
        Self {
            principal: principal.to_owned(),
            user: directory_name(principal, realm),
            sent: None,
        }
    }

    fn sent_as(mut self, name: Option<&String>) -> Self {
        self.sent = name.filter(|name| **name != self.principal).cloned();
        self
    }

    fn requested_as(&self) -> String {
        self.sent
            .as_ref()
            .map(|sent| format!(" (requested as {sent})"))
            .unwrap_or_default()
    }
}

fn row_of(name: &str, realm: &str) -> Option<String> {
    let (parsed, in_realm) = krb5_types::principal_from_unparsed(name, realm).ok()?;
    lookup_principal_id(&parsed, &in_realm).map(|id| row_name(id, realm))
}

pub(crate) fn row_name(id: String, realm: &str) -> String {
    id.strip_suffix(&format!("@{realm}"))
        .map_or_else(|| id.clone(), str::to_owned)
}

/// A row name as kerber-rust names its record: the realm's own rows get `@REALM` back.
fn full_name(row: &str, realm: &str) -> String {
    krb5_types::principal_from_unparsed(row, realm)
        .ok()
        .and_then(|(parsed, in_realm)| lookup_principal_id(&parsed, &in_realm))
        .unwrap_or_else(|| row.to_owned())
}

fn asked<S: AsRef<str>>(names: impl IntoIterator<Item = S>, realm: &str) -> Vec<Named> {
    names
        .into_iter()
        .map(|name| Named::of(name.as_ref(), realm))
        .filter(|named| named.user.is_some())
        .collect()
}

/// The name kadmind peeked at: an alias's target, else the first.
fn peeked(intent: &WriteIntent) -> Option<&String> {
    let at = usize::from(intent.operation == Operation::CreateAlias);
    intent.requested.get(at)
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
    /// MIT's write, unless a name in `new`, or a target in `onto` or past it, is a user's.
    Write {
        new: Vec<Named>,
        onto: Vec<String>,
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
        Operation::Bootstrap => {
            return Ok(Verdict::Write {
                new: Vec::new(),
                onto: Vec::new(),
            });
        }
        _ => {}
    }
    let owned: Vec<&RowChange> = change.rows.iter().filter(|row| row.host_owned).collect();
    let existing = owned.iter().find(|row| row.before.is_some());
    let Some(row) = existing.or_else(|| owned.first()) else {
        let created: Vec<&RowChange> = change.rows.iter().filter(|r| r.before.is_none()).collect();
        let new = asked(
            created
                .iter()
                .filter(|row| row.after.is_some())
                .map(|row| &row.id),
            realm,
        );
        let onto = created
            .iter()
            .filter_map(|row| row.after.as_ref()?.alias_target())
            .collect();
        return Ok(Verdict::Write { new, onto });
    };
    let named = Named::of(&row.id, realm).sent_as(peeked(intent));
    match intent.operation {
        Operation::Unspecified => Err(KerberosStoreError::Refused(format!(
            "an undeclared write to a directory user's principal: {}",
            row.id
        ))),
        Operation::Modify
            if owned.len() == 1 && unlock_only(intent) && unlocked_only(change, realm) =>
        {
            Ok(Verdict::Unlock(named))
        }
        Operation::ChangePassword if owned.len() == 1 => Ok(password_verdict(intent, named)),
        _ => Ok(Verdict::Deny {
            code: KADM5_PROTECT_PRINCIPAL,
            named,
        }),
    }
}

/// `prepare`'s answer from the peek; `commit_change` gives it again from the rows.
pub(crate) fn early(intent: &WriteIntent, target: Option<&TargetPeek>, realm: &str) -> Verdict {
    let at = |at: usize| intent.requested.get(at);
    let ask = |new: Option<&String>, onto: Option<&String>| Verdict::Write {
        new: asked(new, realm),
        onto: onto.cloned().into_iter().collect(),
    };
    let owned = target
        .filter(|peek| peek.host_owned)
        .map(|peek| Named::of(&peek.id, realm).sent_as(peeked(intent)));
    match (intent.operation, target, owned) {
        (Operation::Bootstrap | Operation::Embedded | Operation::Unspecified, _, _)
        | (Operation::Create, Some(_), _) => ask(None, None),
        (Operation::Create, None, _) => ask(at(0), None),
        (Operation::ChangePassword, _, Some(named)) => password_verdict(intent, named),
        (Operation::Modify, _, Some(named)) if unlock_only(intent) => Verdict::Unlock(named),
        (Operation::Delete, _, Some(named)) if named.sent.is_some() => ask(None, None),
        (_, _, Some(named)) => Verdict::Deny {
            code: KADM5_PROTECT_PRINCIPAL,
            named,
        },
        (Operation::Rename, Some(_), None) => ask(at(1), None),
        (Operation::CreateAlias, _, None) => ask(at(0), at(1)),
        _ => ask(None, None),
    }
}

fn unlock_only(intent: &WriteIntent) -> bool {
    let unlock = kadm5_mask::FAIL_AUTH_COUNT;
    intent.client_mask == Some(unlock) || intent.client_mask == Some(unlock | kadm5_mask::TL_DATA)
}

/// One record, in which only the fail count, one `TL_LAST_ADMIN_UNLOCK` and the stamp moved.
fn unlocked_only(change: &HostChange, realm: &str) -> bool {
    let batch = &change.batch;
    let [row] = change.rows.as_slice() else {
        return false;
    };
    let (Some(before), Some(after)) = (&row.before, &row.after) else {
        return false;
    };
    let judged = row_name(row.id.clone(), realm);
    batch.put_policies.is_empty()
        && batch.delete_policies.is_empty()
        && batch.delete_principals.is_empty()
        && batch.upsert_principals.len() == 1
        && batch
            .upsert_principals
            .iter()
            .all(|p| row_name(p.name.clone(), realm) == judged)
        && batch.realm.is_none()
        && row.mask & !UNLOCK_ROW_BITS == 0
        && after.fail_auth_count == 0
        && same_but_unlock(before, after)
        && unlock_entries(before, after)
}

fn tl_of(p: &Principal, of: impl Fn(i32) -> bool) -> Vec<&TlData> {
    p.tl_data.iter().filter(|tl| of(tl.ty)).collect()
}

fn same_but_unlock(a: &Principal, b: &Principal) -> bool {
    let kept = |ty: i32| ty != TL_MOD_PRINC && ty != TL_LAST_ADMIN_UNLOCK;
    a.name == b.name
        && a.realm == b.realm
        && a.keys.len() == b.keys.len()
        && a.key_history.len() == b.key_history.len()
        && a.top_kvno() == b.top_kvno()
        && a.opaque_keys == b.opaque_keys
        && a.salt == b.salt
        && a.max_life == b.max_life
        && a.pw_expire == b.pw_expire
        && a.attributes == b.attributes
        && a.max_renewable_life == b.max_renewable_life
        && a.expiration == b.expiration
        && a.last_success == b.last_success
        && a.last_failed == b.last_failed
        && a.mkvno == b.mkvno
        && a.db_entry_len == b.db_entry_len
        && tl_of(a, kept) == tl_of(b, kept)
        && a.e_data == b.e_data
        && a.rid == b.rid
        && a.s4u_allowed_from == b.s4u_allowed_from
        && a.s4u_allowed_to == b.s4u_allowed_to
        && a.pw_policy == b.pw_policy
        && a.kadm == b.kadm
        && a.string_attrs == b.string_attrs
}

fn unlock_entries(before: &Principal, after: &Principal) -> bool {
    let unlock = |ty: i32| ty == TL_LAST_ADMIN_UNLOCK;
    let stamped = tl_of(after, |ty| ty == TL_MOD_PRINC).len() <= 1;
    let entry = matches!(tl_of(after, unlock).as_slice(), [one] if one.contents.len() == 4);
    stamped && (entry || tl_of(after, unlock) == tl_of(before, unlock))
}

fn password_verdict(intent: &WriteIntent, named: Named) -> Verdict {
    let keepold = intent.keepold.is_some_and(|keepold| keepold != 0);
    let code = match &intent.password {
        _ if keepold || named.user.is_none() => KADM5_PROTECT_PRINCIPAL,
        Some(password) => match std::str::from_utf8(password.as_slice())
            .map(|password| password_rules(password, PASSWORD_MIN_LENGTH))
        {
            Ok(Ok(())) => return Verdict::Password(named),
            Ok(Err(PasswordChangeError::TooShort(_))) => KADM5_PASS_Q_TOOSHORT,
            Ok(Err(_)) | Err(_) => KADM5_PASS_Q_GENERIC,
        },
        None => KADM5_PROTECT_PRINCIPAL,
    };
    Verdict::Deny { code, named }
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
        KADM5_PASS_Q_GENERIC => "PASS_Q_GENERIC",
        _ => "another code",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Code(u32),
    TooShort(usize),
    PolicyUnread,
}

const PROTECTED: Refusal = Refusal::Code(KADM5_PROTECT_PRINCIPAL);

impl Refusal {
    fn of(code: u32) -> Self {
        match code {
            KADM5_PASS_Q_TOOSHORT => Self::TooShort(PASSWORD_MIN_LENGTH),
            code => Self::Code(code),
        }
    }

    fn code(self) -> u32 {
        match self {
            Self::Code(code) => code,
            Self::TooShort(_) => KADM5_PASS_Q_TOOSHORT,
            Self::PolicyUnread => KADM5_PASS_Q_GENERIC,
        }
    }
}

fn denied(intent: &WriteIntent, refusal: Refusal, named: &Named) -> KerberosStoreError {
    let code = refusal.code();
    let cause = match refusal {
        Refusal::PolicyUnread => format!(": {POLICY_UNREAD}"),
        _ => String::new(),
    };
    let text = match refusal {
        Refusal::TooShort(min) => {
            format!("the password is shorter than {min} {PASSWORD_LENGTH_UNIT}")
        }
        Refusal::PolicyUnread => PASSWORD_POLICY_UNREADABLE.to_owned(),
        Refusal::Code(KADM5_PASS_Q_GENERIC) => {
            "the password must be valid UTF-8 without a NUL character (U+0000)".to_owned()
        }
        Refusal::Code(KADM5_AUTH_ADD) => format!(
            "{} is a directory user's name; turn on Kerberos for the user in KLLDAP",
            named.principal
        ),
        Refusal::Code(_) => format!(
            "{} belongs to a directory user; change it in KLLDAP",
            named.principal
        ),
    };
    logged_denial(intent, code, named, &cause, text)
}

fn unprepared(intent: &WriteIntent, named: &Named) -> KerberosStoreError {
    let why = format!(": {UNPREPARED}");
    let text = format!("{UNPREPARED}; try again");
    logged_denial(intent, KADM5_PASS_Q_GENERIC, named, &why, text)
}

fn logged_denial(
    intent: &WriteIntent,
    code: u32,
    named: &Named,
    why: &str,
    text: String,
) -> KerberosStoreError {
    let detail = format!(
        "kadmin {} on {} by {}: {}{why}{}",
        operation_name(intent.operation),
        named.principal,
        client(&intent.caller),
        code_name(code),
        named.requested_as()
    );
    logging::record_kadmin(
        client(&intent.caller),
        LogKind::AccessDenied,
        Some(&named.principal),
        false,
        Some(&detail),
    );
    KerberosStoreError::Denied(Denial {
        kadm5_code: code,
        text,
    })
}

/// A `cpw` held to the user's minimum, at `prepare` and again at the commit.
fn held_to(
    intent: &WriteIntent,
    named: &Named,
    password: &[u8],
    min: usize,
) -> Result<(), KerberosStoreError> {
    let refusal = match std::str::from_utf8(password).map(|text| password_rules(text, min)) {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(PasswordChangeError::TooShort(n))) => Refusal::TooShort(n),
        Ok(Err(_)) | Err(_) => Refusal::Code(KADM5_PASS_Q_GENERIC),
    };
    Err(denied(intent, refusal, named))
}

struct PreparedRecord {
    user: UserId,
    record: Vec<u8>,
    min: usize,
}

impl KerberosStore for SqlRealm {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        let loaded = self.store.load().map_err(store_error)?;
        if self.started.load(Ordering::Acquire) {
            self.queue_statuses();
        }
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
            Verdict::Write { new, onto } => {
                let onto: Vec<Named> = onto.iter().map(|t| Named::of(t, &self.realm)).collect();
                let onto = self.onto(&change.intent, onto);
                self.write_new(change, &new, &onto)
            }
            Verdict::Unlock(named) => {
                let at = lock_clock();
                let by = client(&change.intent.caller);
                let rows = named.user.iter().flat_map(|user| {
                    let target = Some(user.as_str());
                    let detail = Some(UNLOCKED_BY_KADMIN);
                    [
                        HostRow::Unlock {
                            user: user.clone(),
                            at,
                        },
                        HostRow::Log(logging::kadmin_event(
                            by,
                            LogKind::AccountUnlock,
                            target,
                            true,
                            detail,
                        )),
                    ]
                });
                self.write(rows.collect(), change.batch)?;
                if let Some(user) = &named.user {
                    lockout().unlocked(user, at);
                }
                let detail = format!("kadmin unlock by {by}{}", named.requested_as());
                logging::record_kadmin(
                    client(&change.intent.caller),
                    LogKind::KerberosSync,
                    Some(&named.principal),
                    true,
                    Some(&detail),
                );
                Ok(())
            }
            Verdict::Password(named) => self.commit_password(change, &named),
            Verdict::Deny { code, named } => Err(denied(&change.intent, Refusal::of(code), &named)),
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
            Verdict::Write { new, onto } => {
                let onto = self.onto(intent, self.targets(&onto));
                let onto = [onto, self.renamed_alias(intent)].concat();
                self.read_new(intent, &new, &onto).map(|()| None)
            }
            Verdict::Unlock(_) => Ok(None),
            Verdict::Password(named) => self.prepared(intent, &named).map(Some),
            Verdict::Deny { code, named } => Err(denied(intent, Refusal::of(code), &named)),
        }
    }
}

impl Host for SqlRealm {
    fn write_own(&self, change: HostChange, rows: Vec<HostRow>) -> Result<(), KerberosStoreError> {
        self.write(rows, change.batch)
    }

    fn user_disabled(&self, user: &UserId) -> Result<bool, KerberosStoreError> {
        self.store.user_disabled(user).map_err(store_error)
    }

    fn user_synced(&self, user: &UserId) -> Result<bool, KerberosStoreError> {
        self.store.user_synced(user).map_err(store_error)
    }

    fn synced_statuses(&self) -> Result<Vec<(UserId, bool)>, KerberosStoreError> {
        self.store.synced_statuses().map_err(store_error)
    }

    fn directory_users(&self, users: &[UserId]) -> Result<Vec<UserId>, KerberosStoreError> {
        self.store.directory_users(users).map_err(store_error)
    }

    fn start_pass_committed(&self) {
        self.started.store(true, Ordering::Release);
    }

    fn fill_alias_targets(&self, rows: &[(String, String)]) -> Result<u64, KerberosStoreError> {
        self.store.fill_alias_targets(rows).map_err(store_error)
    }

    fn follow_with(&self, follow: Follow) {
        *self.follow.lock().unwrap_or_else(|e| e.into_inner()) = Some(follow);
    }

    fn realm_not_held(&self) -> Option<String> {
        self.store.realm_not_held()
    }

    fn realm_unsettled(&self) -> Option<String> {
        self.store.realm_unsettled()
    }
}

impl SqlRealm {
    /// Off kadmind's thread: the change waits for the store lock kadmind holds until it returns.
    fn queue_follow(&self, user: UserId, client: &str) {
        let follow = self
            .follow
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match (follow, &self.records) {
            (Some(follow), Some(records)) => {
                records.runtime.spawn(follow.run(user, client.to_owned()));
            }
            _ => logging::record_kadmin(
                client,
                LogKind::KerberosSync,
                Some(user.as_str()),
                false,
                Some(NO_FOLLOW),
            ),
        }
    }

    /// A reload opens the realm again; once it has, the marked principals follow the directory.
    fn queue_statuses(&self) {
        let follow = self
            .follow
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (Some(follow), Some(records)) = (follow, &self.records) else {
            return;
        };
        if !self.following.swap(true, Ordering::AcqRel) {
            records
                .runtime
                .spawn(follow.statuses(self.following.clone()));
        }
    }

    fn records(&self) -> Result<&Records, KerberosStoreError> {
        self.records.as_ref().ok_or_else(|| {
            KerberosStoreError::Refused("no password records are wired to this realm".to_owned())
        })
    }

    fn read_new(
        &self,
        intent: &WriteIntent,
        new: &[Named],
        onto: &[Named],
    ) -> Result<(), KerberosStoreError> {
        let users = [users_of(onto), users_of(new)].concat();
        if users.is_empty() {
            return Ok(());
        }
        match self.store.directory_users(&users) {
            Ok(found) => {
                let held = |named: &Named| named.user.as_ref().is_some_and(|u| found.contains(u));
                if let Some(named) = onto.iter().find(|&named| held(named)) {
                    return Err(denied(intent, PROTECTED, named));
                }
                match new.iter().find(|&named| held(named)) {
                    Some(named) => Err(denied(intent, Refusal::Code(KADM5_AUTH_ADD), named)),
                    None => Ok(()),
                }
            }
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
            return Err(denied(intent, PROTECTED, named));
        };
        let records = self.records()?;
        let min = records.hold(intent, named, user, password.as_slice())?;
        let record = records.derive(user, password.as_slice())?;
        Ok(Box::new(PreparedRecord {
            user: user.clone(),
            record,
            min,
        }))
    }

    fn write_new(
        &self,
        change: HostChange,
        new: &[Named],
        onto: &[Named],
    ) -> Result<(), KerberosStoreError> {
        let new_users = users_of(new);
        let mut rows = Vec::new();
        if !onto.is_empty() {
            rows.push(HostRow::NoAliasOnto(self.alias_onto(onto)));
        }
        if !new_users.is_empty() {
            rows.push(HostRow::NoUser(new_users));
        }
        match self.write(rows, change.batch) {
            Err(KerberosStoreError::Refused(why)) if why.starts_with(DIRECTORY_TARGET) => {
                let found = why
                    .strip_prefix(DIRECTORY_TARGET)
                    .and_then(|rest| rest.strip_prefix(": "));
                let named = self.reached(onto, found);
                Err(denied(&change.intent, PROTECTED, &named))
            }
            Err(KerberosStoreError::Refused(why)) if why == DIRECTORY_USER => {
                let refusal = Refusal::Code(KADM5_AUTH_ADD);
                Err(denied(&change.intent, refusal, &one_of(new)))
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
            return Err(denied(&intent, PROTECTED, named));
        };
        let record = match prepared.and_then(|p| p.downcast::<PreparedRecord>().ok()) {
            Some(p) if p.user == user => {
                held_to(&intent, named, password.as_slice(), p.min)?;
                p.record
            }
            _ => {
                warn!(
                    "kadmin change_password for {user}: kadmind's commit came without its \
                     prepared change and is refused, so nothing is derived under the store's lock"
                );
                return Err(unprepared(&intent, named));
            }
        };
        let mut detail = format!("kadmin change_password by {}", client(&intent.caller));
        if self_service(&intent.caller) {
            detail.push_str(" (self-service)");
        }
        detail.push_str(&named.requested_as());
        let row = logging::kadmin_event(
            client(&intent.caller),
            LogKind::PasswordChange,
            Some(&named.principal),
            true,
            Some(&detail),
        );
        let rows = vec![
            HostRow::SetPassword {
                user: user.clone(),
                record,
                now: chrono::Utc::now().naive_utc(),
            },
            HostRow::Log(row.clone()),
        ];
        self.write(rows, batch)?;
        logging::print(&row);
        self.queue_follow(user, client(&intent.caller));
        Ok(())
    }

    /// `row`, then each row name its alias rows lead to, as kerber-rust resolves them.
    fn chain(&self, row: &str) -> Vec<String> {
        let read = self.store.alias_chain(row, MAX_ALIAS_DEPTH);
        read.unwrap_or_else(|e| {
            warn!("The alias rows were not read before a kadmin write; its commit decides: {e}");
            vec![row.to_owned()]
        })
    }

    fn targets(&self, onto: &[String]) -> Vec<Named> {
        let mut named = Vec::new();
        for target in onto {
            named.push(Named::of(target, &self.realm));
            let chain = row_of(target, &self.realm).map(|row| self.chain(&row));
            named.extend(chain.unwrap_or_default().iter().skip(1).map(|hop| {
                Named::of(&full_name(hop, &self.realm), &self.realm).sent_as(Some(target))
            }));
        }
        named.retain(|named| named.user.is_some());
        named
    }

    fn onto(&self, intent: &WriteIntent, named: Vec<Named>) -> Vec<Named> {
        if intent.operation != Operation::Rename {
            return named;
        }
        let sent = peeked(intent);
        named.into_iter().map(|named| named.sent_as(sent)).collect()
    }

    /// A rename of an alias makes a new name for the alias's target, as `CreateAlias` does.
    fn renamed_alias(&self, intent: &WriteIntent) -> Vec<Named> {
        if intent.operation != Operation::Rename {
            return Vec::new();
        }
        let Some(row) = peeked(intent).and_then(|source| row_of(source, &self.realm)) else {
            return Vec::new();
        };
        let named: Vec<Named> = self
            .chain(&row)
            .iter()
            .skip(1)
            .map(|hop| Named::of(&full_name(hop, &self.realm), &self.realm))
            .filter(|named| named.user.is_some())
            .collect();
        self.onto(intent, named)
    }

    fn alias_onto(&self, onto: &[Named]) -> AliasOnto {
        let realm = self.realm.clone();
        AliasOnto {
            targets: onto
                .iter()
                .map(|named| {
                    row_of(&named.principal, &self.realm).unwrap_or_else(|| named.principal.clone())
                })
                .collect(),
            hops: MAX_ALIAS_DEPTH,
            user_of: Arc::new(move |name: &str| directory_name(name, &realm)),
        }
    }

    /// The name the commit found on a target's chain, named as `prepare` names it.
    fn reached(&self, onto: &[Named], found: Option<&str>) -> Named {
        let Some(found) = found else {
            return one_of(onto);
        };
        let start =
            |named: &&Named| row_of(&named.principal, &self.realm).as_deref() == Some(found);
        if let Some(named) = onto.iter().find(start) {
            return named.clone();
        }
        let through = onto
            .first()
            .map(|named| named.sent.as_ref().unwrap_or(&named.principal));
        Named::of(&full_name(found, &self.realm), &self.realm).sent_as(through)
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

fn users_of(names: &[Named]) -> Vec<UserId> {
    names
        .iter()
        .filter_map(|named| named.user.clone())
        .collect()
}

fn one_of(names: &[Named]) -> Named {
    match names {
        [one] => one.clone(),
        _ => Named {
            principal: names
                .iter()
                .map(|named| named.principal.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            user: None,
            sent: None,
        },
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
    use crate::embedded::tests::{TempRealm, synced, unmarked};
    use krb5_kdc::Error as StoreError;
    use krb5_kdc::ModifyPrincipal;
    use krb5_kdc::host::{Caller, RowChange, WriteIntent, conformance};
    use krb5_types::PrincipalName;
    use lldap_domain::types::UserId;
    use lldap_domain_handlers::kerberos::KerberosSync;
    use lldap_domain_handlers::lockout::LockWrite;
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
                .block_on(synced(&embedded, &UserId::new(user), "A-Password-1"))
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
        use lldap_domain_handlers::kerberos::CommitError;
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
        let sync = |password| runtime.block_on(synced(&embedded, &bob, password));
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
        let stalled = match sync("A-Password-2") {
            Err(CommitError::Failed(why)) => why,
            other => panic!("{other:?}"),
        };
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

    fn record_of(pool: &DatabaseConnection, runtime: &Runtime, user: &str) -> Option<Vec<u8>> {
        let query = format!("SELECT password_hash FROM users WHERE user_id = '{user}'");
        let statement = sea_orm::Statement::from_string(pool.get_database_backend(), query);
        let row = runtime.block_on(pool.query_one(statement)).unwrap()?;
        row.try_get::<Option<Vec<u8>>>("", "password_hash").unwrap()
    }

    fn password_commit(
        user: &str,
        record: &[u8],
    ) -> lldap_domain_handlers::kerberos::PasswordCommit {
        lldap_domain_handlers::kerberos::PasswordCommit {
            user: UserId::new(user),
            kind: LogKind::PasswordChange,
            rows: vec![
                HostRow::SetPassword {
                    user: UserId::new(user),
                    record: record.to_vec(),
                    now: chrono::Utc::now().naive_utc(),
                },
                HostRow::Log(logging::event(
                    LogKind::PasswordChange,
                    Some(user),
                    true,
                    None,
                )),
            ],
        }
    }

    fn top_kvno(store: &krb5_kdc::PrincipalStore, user: &str) -> Option<u32> {
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]);
        store.get_name(&name).and_then(|p| p.top_kvno())
    }

    fn one_transaction_on(connect: Reconnect) {
        use lldap_domain_handlers::kerberos::CommitError;
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
        let (change, kvno) = (password_commit, top_kvno);
        let stored = |user: &str| record_of(&pool, &runtime, user);
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
            (Ok(()), true, 1, Some(1)),
            "committed: both new, with its row"
        );

        let carol = runtime.block_on(embedded.commit_password(change("carol", b"c1"), "Carol-1"));
        assert_eq!(carol, Ok(()));
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

    #[derive(Clone, Default)]
    struct Warnings(Arc<Mutex<Vec<String>>>);

    struct Message<'a>(&'a mut String);

    impl tracing::field::Visit for Message<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0.push_str(&format!("{value:?}"));
            }
        }
    }

    impl tracing::Subscriber for Warnings {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                let mut text = String::new();
                event.record(&mut Message(&mut text));
                self.0.lock().unwrap().push(text);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn lost_answer_on(connect: Reconnect) {
        use lldap_domain_handlers::password::ANSWER_LOST;
        use lldap_sql_backend_handler::start_committer_losing_an_answer;
        let warnings = Warnings::default();
        let seen = warnings.clone();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .on_thread_start(move || {
                std::mem::forget(tracing::subscriber::set_default(seen.clone()));
            })
            .build()
            .unwrap();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let pool = connect(&runtime);
        let committer = runtime.block_on(async {
            init_table(&pool).await.unwrap();
            start_committer_losing_an_answer(pool.clone())
        });
        add_user(&pool, &runtime, "bob");
        let host = Arc::new(SqlRealm::new(committer.store()));
        host.start_pass_committed();
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        let stored = |record: &[u8]| record_of(&pool, &runtime, "bob") == Some(record.to_vec());
        let logs = || {
            count(
                &pool,
                &runtime,
                "SELECT COUNT(*) AS n FROM logs WHERE kind = 'password_change'",
            )
        };

        let lost =
            runtime.block_on(embedded.commit_password(password_commit("bob", b"r1"), "Bob-Pass-1"));
        let reopened = boot::open_store(&temp.settings, &profile, host.clone()).unwrap();
        let first = (lost, stored(b"r1"), logs(), top_kvno(&reopened, "bob"));
        let next =
            runtime.block_on(embedded.commit_password(password_commit("bob", b"r2"), "Bob-Pass-2"));
        let then = (next, stored(b"r2"), logs());
        let lines: Vec<String> = warnings
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.contains(ANSWER_LOST))
            .cloned()
            .collect();
        assert_eq!(
            (first, then, lines),
            (
                (Ok(()), true, 1, Some(1)),
                (Ok(()), true, 2),
                vec![format!("The commit for user bob: {ANSWER_LOST}")]
            ),
            "the answer lost after COMMIT: success, one row, the new record, one WARNING"
        );
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_a_lost_answer_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-lost-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("lost.db").display());
        lost_answer_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    #[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
    fn test_a_lost_answer_on_postgres() {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            eprintln!("KLLDAP_TEST_DATABASE_URL is not a postgres URL; skipping");
            return;
        }
        let schema = format!("klldap_lost_{}", std::process::id());
        lost_answer_on(&|runtime| {
            runtime.block_on(async {
                let admin = Database::connect(url.as_str()).await.unwrap();
                for sql in [
                    format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
                    format!("CREATE SCHEMA {schema}"),
                ] {
                    admin.execute_unprepared(&sql).await.unwrap();
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

    fn life_cycle_on(connect: Reconnect) {
        use crate::embedded::ADOPTED;
        use crate::embedded::tests::kinit_code;
        use krb5_types::err::{C_PRINCIPAL_UNKNOWN, CLIENT_REVOKED};
        use lldap_domain::requests::UpdateUserRequest;
        use lldap_domain::types::Attribute;
        use lldap_domain_handlers::kerberos::{CommitError, UserChange, UserStep};
        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let (committer, pool) = committer_on(connect, &runtime);
        for user in ["bob", "carol", "dave", "erin"] {
            add_user(&pool, &runtime, user);
        }
        sql(
            &pool,
            &runtime,
            "INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, \
             uuid, modified_date) VALUES (7, 'grp', 'grp', '2026-01-01 00:00:00', 'uuid-grp', \
             '2026-01-01 00:00:00')",
        );
        for user in ["bob", "dave"] {
            let statement =
                format!("INSERT INTO memberships (user_id, group_id) VALUES ('{user}', 7)");
            sql(&pool, &runtime, &statement);
        }
        let host = Arc::new(SqlRealm::new(committer.store()));
        host.start_pass_committed();
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        for user in ["bob", "carol", "dave"] {
            runtime
                .block_on(synced(&embedded, &UserId::new(user), "A-Password-1"))
                .unwrap();
        }
        unmarked(&embedded, "erin", false);
        let change = |user: &str, step: UserStep| {
            let id = UserId::new(user);
            let (row, kind) = match step {
                UserStep::Delete => (HostRow::DeleteUser(id.clone()), LogKind::UserDelete),
                _ => {
                    let sync = Attribute {
                        name: "kerberossync".into(),
                        value: 1i64.into(),
                    };
                    let request = UpdateUserRequest {
                        user_id: id.clone(),
                        insert_attributes: match step {
                            UserStep::SyncOn => vec![sync],
                            _ => Vec::new(),
                        },
                        delete_attributes: match step {
                            UserStep::SyncOn => Vec::new(),
                            _ => vec!["kerberossync".into()],
                        },
                        ..Default::default()
                    };
                    (HostRow::UpdateUser(request), LogKind::UserUpdate)
                }
            };
            let log = logging::event(kind, Some(user), true, None);
            UserChange {
                user: id,
                step,
                rows: vec![row, HostRow::Log(log)],
            }
        };
        let n = |query: String| count(&pool, &runtime, &query);
        let user_rows = |user: &str| {
            n(format!(
                "SELECT COUNT(*) AS n FROM users WHERE user_id = '{user}'"
            ))
        };
        let synced = |user: &str| {
            n(format!(
                "SELECT COUNT(*) AS n FROM user_attributes WHERE user_attribute_user_id = \
                 '{user}' AND user_attribute_name = 'kerberossync'"
            ))
        };
        let joined = |user: &str| {
            n(format!(
                "SELECT COUNT(*) AS n FROM memberships WHERE user_id = '{user}'"
            ))
        };
        let logs = |kind: &str| {
            n(format!(
                "SELECT COUNT(*) AS n FROM logs WHERE kind = '{kind}'"
            ))
        };
        let both = |user: &str| {
            let reopened = boot::open_store(&temp.settings, &profile, host.clone()).unwrap();
            let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]);
            let kept = reopened
                .get_name(&name)
                .map(|p| (p.host_owned(), p.locked()));
            (state(&store, user), kept)
        };
        let commit = |user: &str, step| runtime.block_on(embedded.commit_user(change(user, step)));

        let marked = commit("carol", UserStep::SyncOn);
        assert_eq!(
            (
                marked,
                synced("carol"),
                both("carol"),
                logs("kerberos_sync")
            ),
            (Some(Ok(())), 1, (Some((true, true)), Some((true, true))), 1),
            "sync on, a marked principal left behind: adopted and disabled, one row"
        );

        let (held_tx, held) = std::sync::mpsc::channel();
        let holder = runtime.spawn({
            let pool = pool.clone();
            async move {
                let txn = pool.begin().await.unwrap();
                let statement = "UPDATE users SET display_name = 'held' WHERE user_id = 'carol'";
                txn.execute_unprepared(statement).await.unwrap();
                held_tx.send(()).unwrap();
                tokio::time::sleep(Duration::from_secs(6)).await;
                txn.rollback().await.unwrap();
            }
        });
        held.recv().unwrap();
        let stalled = commit("carol", UserStep::SyncOff);
        runtime.block_on(holder).unwrap();
        assert_eq!(
            (
                matches!(stalled, Some(Err(CommitError::Failed(_)))),
                synced("carol"),
                both("carol"),
                kinit_code(&store, "carol", "A-Password-1")
            ),
            (
                true,
                1,
                (Some((true, true)), Some((true, true))),
                CLIENT_REVOKED
            ),
            "sync off that fails: the attribute and the adopted principal stay"
        );

        let off = commit("carol", UserStep::SyncOff);
        assert_eq!(
            (
                off,
                synced("carol"),
                both("carol"),
                kinit_code(&store, "carol", "A-Password-1"),
                logs("user_update")
            ),
            (Some(Ok(())), 0, (None, None), C_PRINCIPAL_UNKNOWN, 2),
            "sync off: the attribute and the principal go together"
        );

        let adopted = commit("erin", UserStep::SyncOn);
        let adoption_rows = n(format!(
            "SELECT COUNT(*) AS n FROM logs WHERE kind = 'kerberos_sync' AND detail = '{ADOPTED}'"
        ));
        assert_eq!(
            (
                adopted,
                synced("erin"),
                both("erin"),
                adoption_rows,
                kinit_code(&store, "erin", "Erin-Pass-1")
            ),
            (
                Some(Ok(())),
                1,
                (Some((true, true)), Some((true, true))),
                2,
                CLIENT_REVOKED
            ),
            "sync on, an unmarked principal: adopted and disabled, one row"
        );
        let next = runtime
            .block_on(embedded.commit_password(password_commit("erin", b"e1"), "Erin-Pass-1"));
        assert_eq!(
            (
                next,
                record_of(&pool, &runtime, "erin") == Some(b"e1".to_vec()),
                both("erin"),
                kinit_code(&store, "erin", "Erin-Pass-1")
            ),
            (Ok(()), true, (Some((true, false)), Some((true, false))), 0),
            "the next password change enables it with both forms"
        );

        let deleted = commit("dave", UserStep::Delete);
        assert_eq!(
            (
                deleted,
                user_rows("dave"),
                joined("dave"),
                both("dave"),
                logs("user_delete")
            ),
            (Some(Ok(())), 0, 0, (None, None), 1),
            "delete: the user, its memberships and its principal go together"
        );

        sql(
            &pool,
            &runtime,
            "UPDATE kerberos_realm SET generation = generation + 1",
        );
        let moved = commit("bob", UserStep::Delete);
        let principal_rows =
            n("SELECT COUNT(*) AS n FROM kerberos_principals WHERE name = 'bob'".to_owned());
        assert_eq!(
            (
                matches!(moved, Some(Err(CommitError::Failed(_)))),
                user_rows("bob"),
                joined("bob"),
                (state(&store, "bob"), principal_rows),
                kinit_code(&store, "bob", "A-Password-1"),
                logs("user_delete")
            ),
            (true, 1, 1, (Some((true, false)), 1), 0, 1),
            "a delete whose closure fails: the user stays, with a working kinit"
        );
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    fn sync_races_on(connect: Reconnect) {
        use lldap_domain::requests::UpdateUserRequest;
        use lldap_domain::types::Attribute;
        use lldap_domain_handlers::kerberos::{CommitError, SYNC_CHANGED, UserChange, UserStep};
        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let (committer, pool) = committer_on(connect, &runtime);
        for user in ["bob", "carl"] {
            add_user(&pool, &runtime, user);
        }
        let host = Arc::new(SqlRealm::new(committer.store()));
        host.start_pass_committed();
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        let sync_rows = |user: &str, was: bool, on: Option<bool>| {
            let id = UserId::new(user);
            let attribute = Attribute {
                name: "kerberossync".into(),
                value: 1i64.into(),
            };
            let (insert_attributes, delete_attributes, kind) = match on {
                Some(true) => (vec![attribute], Vec::new(), LogKind::UserUpdate),
                Some(false) => (Vec::new(), vec!["kerberossync".into()], LogKind::UserUpdate),
                None => (Vec::new(), Vec::new(), LogKind::UserDelete),
            };
            let row = match on {
                Some(_) => HostRow::UpdateUser(UpdateUserRequest {
                    user_id: id.clone(),
                    insert_attributes,
                    delete_attributes,
                    ..Default::default()
                }),
                None => HostRow::DeleteUser(id.clone()),
            };
            let log = logging::event(kind, Some(user), true, None);
            vec![HostRow::SyncIs(id, was), row, HostRow::Log(log)]
        };
        let life = |user: &str, step, rows| {
            let change = UserChange {
                user: UserId::new(user),
                step,
                rows,
            };
            runtime.block_on(embedded.commit_user(change))
        };
        let password = |user: &str, record: &[u8], text: &str| {
            let mut change = password_commit(user, record);
            change
                .rows
                .insert(1, HostRow::SyncIs(UserId::new(user), true));
            runtime.block_on(embedded.commit_password(change, text))
        };
        let n = |query: &str| count(&pool, &runtime, query);
        let both = |user: &str| {
            let reopened = boot::open_store(&temp.settings, &profile, host.clone()).unwrap();
            let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]);
            (state(&store, user), reopened.get_name(&name).is_some())
        };
        let changed = || Some(Err(CommitError::Refused(SYNC_CHANGED.to_owned())));

        let on = life("bob", UserStep::SyncOn, sync_rows("bob", false, Some(true)));
        let first = password("bob", b"r1", "Bob-Pass-1");
        let off = life(
            "bob",
            UserStep::SyncOff,
            sync_rows("bob", true, Some(false)),
        );
        assert_eq!(
            (on, first, off, both("bob")),
            (Some(Ok(())), Ok(()), Some(Ok(())), (None, false)),
            "the change before the sync off: both written, and the sync off takes the principal"
        );

        let logs = n("SELECT COUNT(*) AS n FROM logs WHERE kind = 'password_change'");
        let late = password("bob", b"r2", "Bob-Pass-2");
        assert_eq!(
            (
                late,
                both("bob"),
                record_of(&pool, &runtime, "bob"),
                n("SELECT COUNT(*) AS n FROM logs WHERE kind = 'password_change'")
            ),
            (
                Err(CommitError::Refused(SYNC_CHANGED.to_owned())),
                (None, false),
                Some(b"r1".to_vec()),
                logs
            ),
            "the change read sync on before the sync off: refused, no principal, the record kept"
        );

        let synced_attribute = || {
            n(
                "SELECT COUNT(*) AS n FROM user_attributes WHERE user_attribute_user_id = 'bob' \
               AND user_attribute_name = 'kerberossync'",
            )
        };
        let stale = [
            (UserStep::SyncUnchanged, sync_rows("bob", true, Some(true))),
            (UserStep::SyncOff, sync_rows("bob", true, Some(false))),
            (UserStep::Delete, sync_rows("bob", true, None)),
        ];
        for (step, rows) in stale {
            let got = life("bob", step, rows);
            let users = n("SELECT COUNT(*) AS n FROM users WHERE user_id = 'bob'");
            assert_eq!(
                (got, synced_attribute(), users),
                (changed(), 0, 1),
                "{step:?} read sync on before the sync off: refused, nothing written"
            );
        }

        unmarked(&embedded, "carl", false);
        let gone = life(
            "carl",
            UserStep::DeleteWithoutSync,
            sync_rows("carl", false, None),
        );
        assert_eq!(
            (
                gone,
                n("SELECT COUNT(*) AS n FROM users WHERE user_id = 'carl'"),
                state(&store, "carl")
            ),
            (Some(Ok(())), 0, Some((false, false))),
            "a user without sync goes alone: the unmarked principal of its name is not ours"
        );
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_sync_races_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-races-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("races.db").display());
        sync_races_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    fn test_the_life_cycle_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-life-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("life.db").display());
        life_cycle_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    #[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
    fn test_the_life_cycle_on_postgres() {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            eprintln!("KLLDAP_TEST_DATABASE_URL is not a postgres URL; skipping");
            return;
        }
        let schema = format!("klldap_life_{}", std::process::id());
        let made = AtomicBool::new(false);
        life_cycle_on(&|runtime| {
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

    // The principal takes lldap_disabled as read once the change holds the write lock.
    fn status_rows_on(connect: Reconnect) {
        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let (committer, pool) = committer_on(connect, &runtime);
        for user in ["bob", "carol", "dora"] {
            add_user(&pool, &runtime, user);
        }
        sql(
            &pool,
            &runtime,
            "INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, \
             uuid, modified_date) VALUES (7, 'lldap_disabled', 'lldap_disabled', \
             '2026-01-01 00:00:00', 'uuid-disabled', '2026-01-01 00:00:00')",
        );
        let disable = |user: &str| {
            format!("INSERT INTO memberships (user_id, group_id) VALUES ('{user}', 7)")
        };
        let host = Arc::new(SqlRealm::new(committer.store()));
        host.start_pass_committed();
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        let (bob, carol) = (UserId::new("bob"), UserId::new("carol"));
        for user in [&bob, &carol] {
            runtime
                .block_on(synced(&embedded, user, "A-Password-1"))
                .unwrap();
        }
        runtime
            .block_on(embedded.set_principal_enabled(&bob, false))
            .unwrap();
        sql(&pool, &runtime, &disable("carol"));
        let before = (state(&store, "bob"), state(&store, "carol"));
        let enabled =
            runtime.block_on(embedded.commit_password(password_commit("bob", b"b2"), "Bob-Pass-2"));
        let disabled = runtime
            .block_on(embedded.commit_password(password_commit("carol", b"c2"), "Carol-Pass-2"));

        let held = runtime.block_on(embedded.hold_writes());
        let meanwhile = {
            let (pool, statement) = (pool.clone(), disable("dora"));
            async move {
                pool.execute_unprepared(&statement).await.unwrap();
                drop(held);
            }
        };
        let (late, ()) = runtime.block_on(async {
            tokio::join!(
                embedded.commit_password(password_commit("dora", b"d1"), "Dora-Pass-1"),
                meanwhile
            )
        });
        let reopened = boot::open_store(&temp.settings, &profile, host.clone()).unwrap();
        let after: Vec<_> = ["bob", "carol", "dora"]
            .into_iter()
            .map(|user| {
                let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]);
                let kept = reopened
                    .get_name(&name)
                    .map(|p| (p.host_owned(), p.locked()));
                (user, state(&store, user), kept)
            })
            .collect();
        let done = || Ok(());
        assert_eq!(
            (before, (enabled, disabled, late), after),
            (
                (Some((true, true)), Some((true, false))),
                (done(), done(), done()),
                vec![
                    ("bob", Some((true, false)), Some((true, false))),
                    ("carol", Some((true, true)), Some((true, true))),
                    ("dora", Some((true, true)), Some((true, true))),
                ]
            ),
            "bob enabled, carol disabled, dora disabled after the change started"
        );
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_the_principal_follows_lldap_disabled_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-x1-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("status.db").display());
        status_rows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn membership_rows_on(connect: Reconnect) {
        use crate::embedded::tests::kinit_code;
        use krb5_types::err::CLIENT_REVOKED;
        use lldap_domain::types::GroupId;
        use lldap_domain_handlers::handler::UserBackendHandler;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{PasswordSync, change_password_everywhere};
        use lldap_test_utils::recording_log::LogGuard;
        let (runtime, temp, committer, pool, handler, host, store, embedded) =
            wired_realm(connect, &["kim"]);
        sql(
            &pool,
            &runtime,
            "INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, \
             uuid, modified_date) VALUES (7, 'lldap_disabled', 'lldap_disabled', \
             '2026-01-01 00:00:00', 'uuid-disabled', '2026-01-01 00:00:00')",
        );
        set_kerberos_backend(embedded.clone());
        let (kim, group) = (UserId::new("kim"), GroupId(7));
        runtime.block_on(async {
            handler.update_user(sync_request("kim", 1)).await.unwrap();
            change_password_everywhere(
                &handler,
                &kim,
                "Kim-Pass-1",
                PasswordSync::On,
                PASSWORD_MIN_LENGTH,
            )
            .await
            .unwrap();
        });
        let log = LogGuard::install_on_this_thread();
        let n = |query: &str| count(&pool, &runtime, query);
        let seen = || {
            (
                n("SELECT COUNT(*) AS n FROM memberships WHERE user_id = 'kim'"),
                state(&store, "kim"),
                n("SELECT COUNT(*) AS n FROM kerberos_principals WHERE name = 'kim' AND disabled"),
                kinit_code(&store, "kim", "Kim-Pass-1"),
            )
        };
        let rows = |kind: &str| {
            n(&format!(
                "SELECT COUNT(*) AS n FROM logs WHERE kind = '{kind}'"
            ))
        };
        let failures = || {
            let events = log.recorder().take_events().into_iter();
            let failed = events.filter(|e| !e.success);
            failed
                .map(|e| (e.kind, e.detail.unwrap_or_default()))
                .collect::<Vec<_>>()
        };
        let added = runtime.block_on(handler.add_user_to_group(&kim, group));
        let after_add = (added.is_ok(), seen(), rows("membership_add"), failures());
        let removed = runtime.block_on(handler.remove_user_from_group(&kim, group));
        let after_remove = (
            removed.is_ok(),
            seen(),
            rows("membership_remove"),
            failures(),
        );
        runtime
            .block_on(handler.add_user_to_group(&kim, group))
            .unwrap();
        let mut interleaved = Vec::new();
        for remove_first in [true, false] {
            let held = runtime.block_on(embedded.hold_writes());
            let later = Duration::from_millis(50);
            let (removed, added) = runtime.block_on(async {
                let remove = async {
                    tokio::time::sleep(if remove_first { Duration::ZERO } else { later }).await;
                    handler.remove_user_from_group(&kim, group).await
                };
                let add = async {
                    tokio::time::sleep(if remove_first { later } else { Duration::ZERO }).await;
                    handler.add_user_to_group(&kim, group).await
                };
                let release = async move {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    drop(held);
                };
                let (removed, added, ()) = tokio::join!(remove, add, release);
                (removed, added)
            });
            let after = (removed.is_ok(), added.is_ok(), seen(), failures().len());
            interleaved.push(after);
        }
        sql(
            &pool,
            &runtime,
            "UPDATE kerberos_realm SET generation = generation + 1",
        );
        let refused = runtime.block_on(handler.add_user_to_group(&kim, group));
        let refusals: Vec<_> = failures()
            .into_iter()
            .map(|(kind, detail)| (kind, detail.starts_with("the disable of user kim failed: ")))
            .collect();
        let after_refusal = (refused.is_err(), seen(), rows("membership_add"), refusals);
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        assert_eq!(
            (after_add, after_remove),
            (
                (
                    true,
                    (1, Some((true, true)), 1, CLIENT_REVOKED),
                    1,
                    Vec::new()
                ),
                (true, (0, Some((true, false)), 0, 0), 1, Vec::new())
            ),
            "the membership, its row and the principal's status commit together"
        );
        assert_eq!(
            interleaved,
            vec![
                (true, true, (1, Some((true, true)), 1, CLIENT_REVOKED), 0),
                (true, false, (0, Some((true, false)), 0, 0), 1),
            ],
            "a remove and an add queued behind each other, in both orders: the status is the \
             group's as each change commits"
        );
        assert_eq!(
            after_refusal,
            (
                true,
                (0, Some((true, false)), 0, 0),
                3,
                vec![(LogKind::MembershipAdd, true)]
            ),
            "a change whose commit fails leaves both as they were, with one failure row"
        );
        drop((embedded, store, host, temp, handler, log));
        runtime.block_on(committer.shutdown());
    }

    fn sync_window_on(connect: Reconnect) {
        use crate::embedded::tests::kinit_code;
        use krb5_types::err::CLIENT_REVOKED;
        use lldap_domain::types::GroupId;
        use lldap_domain_handlers::handler::UserBackendHandler;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{PasswordSync, change_password_everywhere};
        let (runtime, temp, committer, pool, handler, host, store, embedded) =
            wired_realm(connect, &["lee"]);
        sql(&pool, &runtime, DISABLED_GROUP);
        set_kerberos_backend(embedded.clone());
        let lee = UserId::new("lee");
        runtime.block_on(async {
            handler.update_user(sync_request("lee", 1)).await.unwrap();
            change_password_everywhere(
                &handler,
                &lee,
                "Lee-Pass-1",
                PasswordSync::On,
                PASSWORD_MIN_LENGTH,
            )
            .await
            .unwrap();
        });
        let attribute = "FROM user_attributes WHERE user_attribute_user_id = 'lee' AND \
                         user_attribute_name = 'kerberossync'";
        sql(
            &pool,
            &runtime,
            &format!("CREATE TABLE saved_sync AS SELECT * {attribute}"),
        );
        sql(&pool, &runtime, &format!("DELETE {attribute}"));
        let before = state(&store, "lee");
        let held = runtime.block_on(embedded.hold_writes());
        let window = {
            let pool = pool.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let statement = "INSERT INTO user_attributes SELECT * FROM saved_sync";
                pool.execute_unprepared(statement).await.unwrap();
                drop(held);
            }
        };
        let (added, ()) = runtime
            .block_on(async { tokio::join!(handler.add_user_to_group(&lee, GroupId(7)), window) });
        let n = |query: &str| count(&pool, &runtime, query);
        let after = (
            added.is_ok(),
            n("SELECT COUNT(*) AS n FROM memberships WHERE user_id = 'lee'"),
            state(&store, "lee"),
            n("SELECT COUNT(*) AS n FROM kerberos_principals WHERE name = 'lee' AND disabled"),
            kinit_code(&store, "lee", "Lee-Pass-1"),
            n("SELECT COUNT(*) AS n FROM logs WHERE kind = 'membership_add'"),
        );
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        assert_eq!(
            (before, after),
            (
                Some((true, false)),
                (true, 1, Some((true, true)), 1, CLIENT_REVOKED, 1)
            ),
            "the door read the user without sync; sync turned on while it waited for the lock: \
             the sync read under the lock disables the principal with the membership"
        );
        drop((embedded, store, host, temp, handler));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_a_sync_turned_on_while_a_disable_waits_disables_the_principal_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-window-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("window.db").display());
        sync_window_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    const DISABLED_GROUP: &str = "INSERT INTO groups (group_id, display_name, \
         lowercase_display_name, creation_date, uuid, modified_date) VALUES (7, 'lldap_disabled', \
         'lldap_disabled', '2026-01-01 00:00:00', 'uuid-disabled', '2026-01-01 00:00:00')";

    fn taken_over_rows_on(connect: Reconnect) {
        use crate::embedded::DISABLED_AT_OPEN;
        use crate::embedded::tests::ask;
        use krb5_types::err::CLIENT_REVOKED;
        use lldap_domain_handlers::handler::UserBackendHandler;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{PasswordSync, change_password_everywhere};
        use lldap_sql_backend_handler::start_committer_watching_for;
        let (runtime, temp, committer, pool, handler, host, store, embedded) =
            wired_realm(connect, &["kim"]);
        set_kerberos_backend(embedded.clone());
        let kim = UserId::new("kim");
        runtime.block_on(async {
            handler.update_user(sync_request("kim", 1)).await.unwrap();
            change_password_everywhere(
                &handler,
                &kim,
                "Kim-Pass-1",
                PasswordSync::On,
                PASSWORD_MIN_LENGTH,
            )
            .await
            .unwrap();
        });
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
        for statement in [
            "UPDATE kerberos_realm SET open = true",
            DISABLED_GROUP,
            "INSERT INTO memberships (user_id, group_id) VALUES ('kim', 7)",
        ] {
            sql(&pool, &runtime, statement);
        }
        let earlier = sync_details(&pool, &runtime, "kim").len();
        let watch = Duration::from_millis(500);
        let watching =
            runtime.block_on(async { start_committer_watching_for(pool.clone(), watch) });
        let records = Records {
            handler: Arc::new(handler.clone()),
            policies: Arc::new(handler.clone()),
            runtime: runtime.handle().clone(),
        };
        let started = std::time::Instant::now();
        let (embedded, opened) =
            EmbeddedKerberos::open(&temp.settings, watching.store(), records).unwrap();
        let watched = started.elapsed() >= watch;
        let disabled = count(
            &pool,
            &runtime,
            "SELECT COUNT(*) AS n FROM kerberos_principals WHERE name = 'kim' AND disabled",
        );
        let rows = sync_details(&pool, &runtime, "kim").split_off(earlier);
        let asked = ask(opened.kdc_udp(), "kim", "Kim-Pass-1");
        let served = std::time::Instant::now();
        let threads = opened.serve().unwrap();
        let (answered, code) = asked.join().unwrap();
        threads.stop();
        assert_eq!(
            (watched, disabled, rows, answered > served, code),
            (
                true,
                1,
                vec![DISABLED_AT_OPEN.to_owned()],
                true,
                CLIENT_REVOKED
            ),
            "the server that takes the realm over sets the status before its KDC answers"
        );
        drop((embedded, temp, handler));
        runtime.block_on(watching.shutdown());
    }

    #[test]
    #[serial]
    fn test_a_server_that_takes_the_realm_over_sets_each_status_before_it_serves_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-taken-over-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("taken-over.db").display());
        taken_over_rows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn turn_rows_on(connect: Reconnect) {
        use crate::embedded::{DISABLED_AT_TURN, ENABLED_AT_TURN};
        use lldap_domain_handlers::handler::UserBackendHandler;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{PasswordSync, change_password_everywhere};
        let (runtime, temp, committer, pool, handler, host, store, embedded) =
            wired_realm(connect, &["hal"]);
        set_kerberos_backend(embedded.clone());
        let hal = UserId::new("hal");
        runtime.block_on(async {
            handler.update_user(sync_request("hal", 1)).await.unwrap();
            change_password_everywhere(
                &handler,
                &hal,
                "Hal-Pass-1",
                PasswordSync::On,
                PASSWORD_MIN_LENGTH,
            )
            .await
            .unwrap();
        });
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        sql(&pool, &runtime, DISABLED_GROUP);
        let earlier = sync_details(&pool, &runtime, "hal").len();
        let turns = {
            let _entered = runtime.enter();
            embedded.follow_every(Duration::from_millis(200))
        };
        let followed = |locked: bool| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while state(&store, "hal") != Some((true, locked))
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            std::thread::sleep(Duration::from_millis(600));
            let rows = sync_details(&pool, &runtime, "hal").split_off(earlier);
            (rows, state(&store, "hal"))
        };
        sql(
            &pool,
            &runtime,
            "INSERT INTO memberships (user_id, group_id) VALUES ('hal', 7)",
        );
        let disabled = followed(true);
        sql(
            &pool,
            &runtime,
            "DELETE FROM memberships WHERE user_id = 'hal'",
        );
        let enabled = followed(false);
        turns.abort();
        let (disabled_row, enabled_row) = (DISABLED_AT_TURN.to_owned(), ENABLED_AT_TURN.to_owned());
        assert_eq!(
            (disabled, enabled),
            (
                (vec![disabled_row.clone()], Some((true, true))),
                (vec![disabled_row, enabled_row], Some((true, false)))
            ),
            "a membership changed in the database reaches the principal at the next turn, once, \
             with its row in the same transaction"
        );
        drop((embedded, store, host, temp, handler));
        runtime.block_on(committer.shutdown());
    }

    fn leftover_rows_on(connect: Reconnect) {
        use crate::embedded::REMOVED_AT_TURN;
        use crate::embedded::tests::kinit_code;
        use krb5_types::err::C_PRINCIPAL_UNKNOWN;
        use lldap_domain_handlers::handler::UserBackendHandler;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{PasswordSync, change_password_everywhere};
        let (runtime, temp, committer, pool, handler, host, store, embedded) =
            wired_realm(connect, &["gus", "ida"]);
        set_kerberos_backend(embedded.clone());
        runtime.block_on(async {
            for user in ["gus", "ida"] {
                handler.update_user(sync_request(user, 1)).await.unwrap();
                let password = format!("{user}-Pass-1");
                let id = UserId::new(user);
                change_password_everywhere(
                    &handler,
                    &id,
                    &password,
                    PasswordSync::On,
                    PASSWORD_MIN_LENGTH,
                )
                .await
                .unwrap();
            }
        });
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        for statement in [
            "DELETE FROM user_attributes WHERE user_attribute_user_id IN ('gus', 'ida')",
            "DELETE FROM users WHERE user_id = 'gus'",
        ] {
            sql(&pool, &runtime, statement);
        }
        let tickets = || {
            (
                kinit_code(&store, "gus", "gus-Pass-1"),
                kinit_code(&store, "ida", "ida-Pass-1"),
            )
        };
        let before = tickets();
        let turns = {
            let _entered = runtime.enter();
            embedded.follow_every(Duration::from_millis(200))
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while (state(&store, "gus").is_some() || state(&store, "ida").is_some())
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(600));
        turns.abort();
        let principals = count(
            &pool,
            &runtime,
            "SELECT COUNT(*) AS n FROM kerberos_principals WHERE name IN ('gus', 'ida')",
        );
        let rows = (
            sync_details(&pool, &runtime, "gus"),
            sync_details(&pool, &runtime, "ida"),
        );
        assert_eq!(
            (before, tickets(), principals, rows),
            (
                (0, 0),
                (C_PRINCIPAL_UNKNOWN, C_PRINCIPAL_UNKNOWN),
                0,
                (
                    vec![format!("{REMOVED_AT_TURN}: user gone")],
                    vec![format!("{REMOVED_AT_TURN}: no sync")]
                )
            ),
            "a user deleted, and a sync turned off, where the realm could not follow: the \
             holder's next turn removes the principal, once, with its row"
        );
        drop((embedded, store, host, temp, handler));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_the_holder_removes_a_principal_left_behind_at_its_turn_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-leftover-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("leftover.db").display());
        leftover_rows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    fn test_the_holder_follows_lldap_disabled_at_each_turn_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-turns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("turns.db").display());
        turn_rows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    fn test_lldap_disabled_and_the_principal_commit_together_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-disabled-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("disabled.db").display());
        membership_rows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    fn test_every_committed_user_write_reaches_the_cache_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-e0-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("cache.db").display());
        cache_rows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cache_rows_on(connect: Reconnect) {
        use crate::admission::tests::{kinit, with_verdict};
        use lldap_domain::requests::{CreateUserRequest, UpdateUserRequest};
        use lldap_domain::types::Attribute;
        use lldap_domain_handlers::enforcement::{CacheFollower, policy_cache};
        use lldap_domain_handlers::handler::UserBackendHandler;
        use lldap_domain_handlers::kerberos::set_thread_kerberos_backend;
        use lldap_domain_handlers::password::create_synced_user;
        use lldap_test_utils::enforcement::EnforcementGuard;
        const PASSWORD: &str = "E0-Ldap-Add-1";
        let (ldap_add, synced_create, plain) = ("e0ldapadd", "e0gqlsync", "e0plain");
        let (runtime, _temp, committer, _pool, handler, host, store, embedded) =
            wired_realm(connect, &[]);
        let follower = CacheFollower::new(handler.clone(), policy_cache());
        embedded.follow_commits(Arc::new(follower));
        with_verdict(&store);
        let decides = |value: &str| value != "always";
        let _guard =
            EnforcementGuard::deciding(&[ldap_add, synced_create, plain], "enable-mfa", decides);
        set_thread_kerberos_backend(Some(embedded.clone()));
        let ou = |value: &str| Attribute {
            name: "ou".into(),
            value: value.to_owned().into(),
        };
        let sync = || Attribute {
            name: "kerberossync".into(),
            value: 1_i64.into(),
        };
        let create = |user: &str, attributes: Vec<Attribute>| CreateUserRequest {
            user_id: UserId::new(user),
            email: format!("{user}@example.com").into(),
            attributes,
            ..Default::default()
        };
        let cached = |user: &str| {
            let entries = policy_cache().get();
            entries.ous_of_users.get(&UserId::new(user)).cloned()
        };
        let labs = || Some("people\\labs".to_owned());
        let people = || Some("people".to_owned());
        let rows = [
            (
                "an LDAP Add with a password, synced: realm commit",
                ldap_add,
                labs(),
            ),
            (
                "a GraphQL create, synced: realm commit",
                synced_create,
                people(),
            ),
            ("a plain create", plain, people()),
            ("an OU move: plain", plain, labs()),
            (
                "an OU move with sync off: realm commit",
                synced_create,
                labs(),
            ),
            ("a delete: realm commit", synced_create, None),
        ];
        for (row, user, expected) in rows {
            let done = runtime.block_on(async {
                match row {
                    "an LDAP Add with a password, synced: realm commit" => {
                        let request = create(user, vec![ou("people\\labs"), sync()]);
                        create_synced_user(&handler, request, PASSWORD, PASSWORD_MIN_LENGTH)
                            .await
                            .map_err(|e| e.to_string())
                    }
                    "a GraphQL create, synced: realm commit" => {
                        let request = create(user, vec![ou("people"), sync()]);
                        handler
                            .create_user(request)
                            .await
                            .map_err(|e| e.to_string())
                    }
                    "a plain create" => {
                        let request = create(user, vec![ou("people")]);
                        handler
                            .create_user(request)
                            .await
                            .map_err(|e| e.to_string())
                    }
                    "a delete: realm commit" => {
                        let deleted = handler.delete_user(&UserId::new(user)).await;
                        deleted.map_err(|e| e.to_string())
                    }
                    _ => {
                        let sync_off = user == synced_create;
                        let request = UpdateUserRequest {
                            user_id: UserId::new(user),
                            insert_attributes: vec![ou("people\\labs")],
                            delete_attributes: sync_off
                                .then(|| "kerberossync".into())
                                .into_iter()
                                .collect(),
                            ..Default::default()
                        };
                        handler
                            .update_user(request)
                            .await
                            .map_err(|e| e.to_string())
                    }
                }
            });
            assert_eq!((done, cached(user)), (Ok(()), expected), "{row}");
            if row.starts_with("an LDAP Add") {
                let first = kinit(&store, user, Some(PASSWORD)).0;
                assert_eq!(
                    first, 0,
                    "the user an LDAP Add made is found by the next kinit"
                );
            }
        }
        set_thread_kerberos_backend(None);
        drop((embedded, store, host, handler));
        runtime.block_on(committer.shutdown());
    }

    type Realm = (
        Runtime,
        TempRealm,
        KerberosCommitterHandle,
        DatabaseConnection,
        lldap_sql_backend_handler::SqlBackendHandler,
        Arc<SqlRealm>,
        krb5_kdc::SharedDump,
        Arc<EmbeddedKerberos>,
    );

    fn wired_realm(connect: Reconnect, users: &[&str]) -> Realm {
        wired_realm_with(connect, users, None, None)
    }

    fn wired_realm_with(
        connect: Reconnect,
        users: &[&str],
        cache: Option<&'static lldap_domain_handlers::enforcement::PolicyCache>,
        policies: Option<Arc<dyn PolicyBackendHandler>>,
    ) -> Realm {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_sql_backend_handler::SqlBackendHandler;
        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let (committer, pool) = committer_on(connect, &runtime);
        for user in users {
            add_user(&pool, &runtime, user);
        }
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let handler = match cache {
            Some(cache) => handler.with_policy_cache(cache),
            None => handler,
        };
        let policies: Arc<dyn PolicyBackendHandler> = match policies {
            Some(policies) => policies,
            None => Arc::new(handler.clone()),
        };
        let records = Records {
            handler: Arc::new(handler.clone()),
            policies,
            runtime: runtime.handle().clone(),
        };
        let host = Arc::new(SqlRealm::new(committer.store()).serving("EXAMPLE.COM", Some(records)));
        host.start_pass_committed();
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        (
            runtime,
            temp,
            committer,
            pool,
            handler,
            host,
            store,
            Arc::new(embedded),
        )
    }

    fn sync_request(user: &str, on: i64) -> lldap_domain::requests::UpdateUserRequest {
        lldap_domain::requests::UpdateUserRequest {
            user_id: UserId::new(user),
            insert_attributes: vec![lldap_domain::types::Attribute {
                name: "kerberossync".into(),
                value: on.into(),
            }],
            ..Default::default()
        }
    }

    fn adopted_cpw_on(connect: Reconnect) {
        use crate::embedded::ENABLED_AFTER_CPW;
        use crate::embedded::tests::kinit_code;
        use krb5_types::err::CLIENT_REVOKED;
        use lldap_domain_handlers::handler::{BindRequest, LoginHandler};
        use lldap_domain_handlers::kerberos::{UserChange, UserStep};
        use lldap_test_utils::recording_log::LogGuard;
        const OLD: &str = "Dora-Old-Pass-1";
        const CPW: &str = "Dora-Cpw-Pass-2";
        let log = LogGuard::install();
        let (runtime, temp, committer, pool, handler, host, store, embedded) =
            wired_realm(connect, &["dora"]);
        sql(
            &pool,
            &runtime,
            "INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, \
             uuid, modified_date) VALUES (7, 'lldap_disabled', 'lldap_disabled', \
             '2026-01-01 00:00:00', 'uuid-disabled', '2026-01-01 00:00:00')",
        );
        let dora = name("dora");
        let etypes: Vec<krb5_crypto::KeySalt> = temp
            .settings
            .supported_enctypes
            .iter()
            .map(|&e| e.into())
            .collect();
        unmarked(&embedded, "dora", false);
        store
            .write()
            .unwrap()
            .change_committing(committing(&*host), |s| {
                let password = OLD.as_bytes();
                s.set_password_etypes_keepold_n_in(
                    &dora,
                    "EXAMPLE.COM",
                    password,
                    0,
                    "test",
                    &etypes,
                )
            })
            .unwrap()
            .unwrap();
        let adopt = UserChange {
            user: UserId::new("dora"),
            step: UserStep::SyncOn,
            rows: vec![HostRow::UpdateUser(sync_request("dora", 1))],
        };
        let adopted = runtime.block_on(embedded.commit_user(adopt));
        let while_adopted = (state(&store, "dora"), kinit_code(&store, "dora", OLD));
        log.recorder().take_events();
        let fill = with_password(CPW, 0);
        let intent = intent_of(Operation::ChangePassword, kadmin(false), &["dora"], &fill);
        let edit = |s: &mut krb5_kdc::PrincipalStore| {
            let password = CPW.as_bytes();
            s.set_password_etypes_keepold_n_in(&dora, "EXAMPLE.COM", password, 0, ADMIN, &etypes)
        };
        let cpw = kadmin_write(&store, true, intent, &dora, &edit);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut followed = Vec::new();
        while followed.is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
            let events = log.recorder().take_events().into_iter();
            followed.extend(
                events
                    .filter(|e| e.kind == LogKind::KerberosSync)
                    .map(|e| (e.protocol, e.actor, e.target, e.success, e.detail)),
            );
        }
        let binds = |password: &str| {
            let request = BindRequest {
                name: UserId::new("dora"),
                password: password.to_owned(),
            };
            runtime.block_on(handler.bind(request)).is_ok()
        };
        assert_eq!(
            (
                adopted,
                while_adopted,
                cpw,
                state(&store, "dora"),
                kinit_code(&store, "dora", CPW),
                (binds(CPW), binds(OLD)),
                followed
            ),
            (
                Some(Ok(())),
                (Some((true, true)), CLIENT_REVOKED),
                "written".to_owned(),
                Some((true, false)),
                0,
                (true, false),
                vec![(
                    logging::Protocol::Kadmin,
                    Some(ADMIN.to_owned()),
                    Some("dora".to_owned()),
                    true,
                    Some(ENABLED_AFTER_CPW.to_owned())
                )]
            ),
            "adopt, kadmin cpw, then enabled with both forms"
        );
        drop((embedded, store, host, temp));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_kadmin_cpw_on_an_adopted_principal_enables_it_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-cpw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("cpw.db").display());
        adopted_cpw_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn minimums(
        answers: &'static [Option<usize>],
    ) -> (Arc<dyn PolicyBackendHandler>, Arc<AtomicUsize>) {
        let asked = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&asked);
        let mut mock = lldap_test_utils::MockTestBackendHandler::new();
        mock.expect_bounded_policy_entry().returning(move |user| {
            let at = count.fetch_add(1, Ordering::SeqCst);
            match answers.get(at).copied().flatten() {
                Some(min) => Ok(lldap_test_utils::minimum_entry(user, min)),
                None => Err(sea_orm::DbErr::Custom("the policy store is down".to_owned()).into()),
            }
        });
        let policies: Arc<dyn PolicyBackendHandler> = Arc::new(mock);
        (policies, asked)
    }

    type HeldCpw = ((String, Option<String>), Rows, bool, usize);

    fn held_cpw(
        guard: &lldap_test_utils::recording_log::LogGuard,
        declared: bool,
        password: &'static str,
        answers: &'static [Option<usize>],
    ) -> HeldCpw {
        let (policies, count) = minimums(answers);
        let memory = |runtime: &Runtime| sqlite_one_connection("sqlite::memory:", runtime);
        let (runtime, temp, committer, pool, _handler, host, store, embedded) =
            wired_realm_with(&memory, &["dora"], None, Some(policies));
        runtime
            .block_on(synced(&embedded, &UserId::new("dora"), "Dora-Password-0"))
            .unwrap();
        let etypes: Vec<krb5_crypto::KeySalt> = temp
            .settings
            .supported_enctypes
            .iter()
            .map(|&e| e.into())
            .collect();
        let dora = name("dora");
        let before = record_of(&pool, &runtime, "dora");
        guard.recorder().take_events();
        let fill = with_password(password, 0);
        let intent = intent_of(Operation::ChangePassword, kadmin(false), &["dora"], &fill);
        let edit = |s: &mut krb5_kdc::PrincipalStore| {
            let bytes = password.as_bytes();
            s.set_password_etypes_keepold_n_in(&dora, "EXAMPLE.COM", bytes, 0, ADMIN, &etypes)
        };
        let answered = match kadmin_try(&store, declared, intent, &dora, &edit) {
            Ok(()) => ("written".to_owned(), None),
            Err(StoreError::Host(KerberosStoreError::Denied(denial))) => {
                (code_name(denial.kadm5_code).to_owned(), Some(denial.text))
            }
            Err(e) => (e.to_string(), None),
        };
        let denials: Rows = guard
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.kind == LogKind::AccessDenied)
            .map(|e| (e.kind, e.target, e.detail))
            .collect();
        let moved = record_of(&pool, &runtime, "dora") != before;
        drop((embedded, store, host, temp));
        runtime.block_on(committer.shutdown());
        (answered, denials, moved, count.load(Ordering::SeqCst))
    }

    fn held_cpw_wanted(answer: (&str, Option<&str>), asked: usize, code: &str) -> HeldCpw {
        let written = answer.0 == "written";
        let logged = match written {
            true => Vec::new(),
            false => denial("dora@EXAMPLE.COM", "change_password", code),
        };
        let answer = (answer.0.to_owned(), answer.1.map(str::to_owned));
        (answer, logged, written, asked)
    }

    #[test]
    #[serial]
    fn test_a_kadmin_cpw_is_held_to_the_users_minimum_read_once_at_prepare() {
        use lldap_test_utils::recording_log::LogGuard;
        const SHORT_12: &str = "the password is shorter than 12 characters";
        type Row = (
            &'static str,
            &'static str,
            &'static [Option<usize>],
            (&'static str, Option<&'static str>),
            usize,
            &'static str,
        );
        let rows: [Row; 6] = [
            (
                "7 characters: the floor, before any read",
                "Short-7",
                &[Some(12)],
                (
                    "PASS_Q_TOOSHORT",
                    Some("the password is shorter than 8 characters"),
                ),
                0,
                "PASS_Q_TOOSHORT",
            ),
            (
                "11 characters, minimum 12",
                "Dora-Pass-1",
                &[Some(12)],
                ("PASS_Q_TOOSHORT", Some(SHORT_12)),
                1,
                "PASS_Q_TOOSHORT",
            ),
            (
                "11 characters in 13 bytes, minimum 12",
                "Dörä-Pass-1",
                &[Some(12)],
                ("PASS_Q_TOOSHORT", Some(SHORT_12)),
                1,
                "PASS_Q_TOOSHORT",
            ),
            (
                "12 characters, minimum 12, and 20 if asked again",
                "Dora-Pass-12",
                &[Some(12), Some(20)],
                ("written", None),
                1,
                "",
            ),
            (
                "12 characters in 14 bytes, minimum 12",
                "Dörä-Pass-12",
                &[Some(12)],
                ("written", None),
                1,
                "",
            ),
            (
                "the policy not read",
                "Dora-Pass-12",
                &[None],
                (
                    "PASS_Q_GENERIC",
                    Some("the password policy could not be read; try again"),
                ),
                1,
                "PASS_Q_GENERIC: the password policy could not be read",
            ),
        ];
        assert_eq!(
            rows.map(|(_, password, ..)| (password.chars().count(), password.len())),
            [(7, 7), (11, 11), (11, 13), (12, 12), (12, 14), (12, 12)]
        );
        let guard = LogGuard::install();
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (label, password, answers, answer, asked, code) in rows {
            got.push((label, held_cpw(&guard, true, password, answers)));
            want.push((label, held_cpw_wanted(answer, asked, code)));
        }
        assert_eq!(
            got, want,
            "a kadmin cpw is held to the user's minimum, read once, at prepare"
        );
    }

    #[test]
    #[serial]
    fn test_a_cpw_kadmind_did_not_prepare_is_refused_without_a_read() {
        use lldap_test_utils::recording_log::LogGuard;
        type Row = (&'static str, &'static str, &'static [Option<usize>]);
        let guard = LogGuard::install();
        let rows: [Row; 3] = [
            ("11 characters, minimum 12", "Dora-Pass-1", &[Some(12)]),
            ("12 characters, minimum 12", "Dora-Pass-12", &[Some(12)]),
            (
                "12 characters, the policy store down",
                "Dora-Pass-12",
                &[None],
            ),
        ];
        let refused = held_cpw_wanted(
            (
                "PASS_Q_GENERIC",
                Some("the change could not be prepared; try again"),
            ),
            0,
            "PASS_Q_GENERIC: the change could not be prepared",
        );
        for (label, password, answers) in rows {
            let got = held_cpw(&guard, false, password, answers);
            assert_eq!(
                got, refused,
                "no prepare, {label}: no read, the record unchanged"
            );
        }
    }

    #[test]
    #[serial]
    fn test_a_held_database_never_holds_a_kadmin_cpw_past_the_minimums_bound() {
        use lldap_domain_handlers::enforcement::PolicyCache;
        use lldap_test_utils::recording_log::LogGuard;
        const PASSWORD: &str = "Dora-Pass-12";
        let guard = LogGuard::install();
        let memory = |runtime: &Runtime| sqlite_one_connection("sqlite::memory:", runtime);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let (runtime, temp, committer, pool, _handler, host, store, embedded) =
            wired_realm_with(&memory, &["dora"], Some(cache), None);
        runtime
            .block_on(synced(&embedded, &UserId::new("dora"), "Dora-Password-0"))
            .unwrap();
        let etypes: Vec<krb5_crypto::KeySalt> = temp
            .settings
            .supported_enctypes
            .iter()
            .map(|&e| e.into())
            .collect();
        let dora = name("dora");
        let before = record_of(&pool, &runtime, "dora");
        guard.recorder().take_events();
        let (held_tx, held) = std::sync::mpsc::channel();
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let holder = runtime.spawn({
            let pool = pool.clone();
            async move {
                let txn = pool.begin().await.unwrap();
                held_tx.send(()).unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(10), released).await;
                txn.rollback().await.unwrap();
            }
        });
        held.recv().unwrap();
        let fill = with_password(PASSWORD, 0);
        let intent = intent_of(Operation::ChangePassword, kadmin(false), &["dora"], &fill);
        let edit = |s: &mut krb5_kdc::PrincipalStore| {
            let bytes = PASSWORD.as_bytes();
            s.set_password_etypes_keepold_n_in(&dora, "EXAMPLE.COM", bytes, 0, ADMIN, &etypes)
        };
        let started = std::time::Instant::now();
        let answered = match kadmin_try(&store, true, intent, &dora, &edit) {
            Ok(()) => ("written".to_owned(), String::new()),
            Err(StoreError::Host(KerberosStoreError::Denied(denial))) => {
                (code_name(denial.kadm5_code).to_owned(), denial.text)
            }
            Err(e) => ("another answer".to_owned(), e.to_string()),
        };
        let (took, still_held) = (started.elapsed(), !holder.is_finished());
        let _ = release.send(());
        runtime.block_on(holder).unwrap();
        let denials: Rows = guard
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.kind == LogKind::AccessDenied)
            .map(|e| (e.kind, e.target, e.detail))
            .collect();
        let unchanged = record_of(&pool, &runtime, "dora") == before;
        assert_eq!(
            (answered, denials, unchanged),
            (
                (
                    "PASS_Q_GENERIC".to_owned(),
                    "the password policy could not be read; try again".to_owned()
                ),
                denial(
                    "dora@EXAMPLE.COM",
                    "change_password",
                    "PASS_Q_GENERIC: the password policy could not be read"
                ),
                true
            ),
            "the minimum not read within its bound: the generic refusal, the record unchanged"
        );
        assert!(
            still_held
                && took >= POLICY_READ_WAIT
                && took < POLICY_READ_WAIT + Duration::from_secs(3),
            "the cpw was answered after {took:?}, the database still held: {still_held}"
        );
        drop((embedded, store, host, temp));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_kadminds_wait_for_the_minimum_ends_at_its_bound_on_a_runtime_that_never_runs_it() {
        type Answer = ((String, String), usize, bool);
        const PASSWORD: &[u8] = b"Dora-Pass-12";
        let idle = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let busy = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (blocked_tx, blocked) = std::sync::mpsc::channel();
        busy.spawn(async move {
            blocked_tx.send(()).unwrap();
            let _ = released.recv_timeout(Duration::from_secs(20));
        });
        blocked.recv().unwrap();
        let named = Named::of("dora@EXAMPLE.COM", "EXAMPLE.COM");
        let mut intent = WriteIntent::new(Operation::ChangePassword, Caller::Embedder);
        intent.password = Some(Zeroizing::new(PASSWORD.to_vec()));
        intent.keepold = Some(0);
        let held = |runtime: &tokio::runtime::Handle| -> Answer {
            let (policies, asked) = minimums(&[Some(8)]);
            let records = Records {
                handler: Arc::new(lldap_test_utils::MockTestBackendHandler::new()),
                policies,
                runtime: runtime.clone(),
            };
            let started = std::time::Instant::now();
            let answer = match records.hold(&intent, &named, &UserId::new("dora"), PASSWORD) {
                Ok(min) => (format!("held to {min}"), String::new()),
                Err(KerberosStoreError::Denied(denial)) => {
                    (code_name(denial.kadm5_code).to_owned(), denial.text)
                }
                Err(e) => ("another answer".to_owned(), e.to_string()),
            };
            let took = started.elapsed();
            let bounded =
                took >= POLICY_READ_WAIT && took < POLICY_READ_WAIT + Duration::from_secs(3);
            (answer, asked.load(Ordering::SeqCst), bounded)
        };
        let got = [
            ("current_thread, never driven", held(idle.handle())),
            ("one worker, blocked", held(busy.handle())),
        ];
        let _ = release.send(());
        let refused = (
            (
                "PASS_Q_GENERIC".to_owned(),
                "the password policy could not be read; try again".to_owned(),
            ),
            0,
            true,
        );
        assert_eq!(
            got,
            [
                ("current_thread, never driven", refused.clone()),
                ("one worker, blocked", refused),
            ],
            "the unreadable refusal at the bound, the read never run"
        );
        let short = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let derived = answer_within(idle.handle(), short, async { 7 });
        let took = started.elapsed();
        let driven = answer_within(busy.handle(), Duration::from_secs(10), async { 7 });
        assert_eq!(
            (
                derived,
                took >= short && took < short + Duration::from_secs(3),
                driven
            ),
            (Err("no answer within 200ms".to_owned()), true, Ok(7)),
            "the derive's wait has the same bound: {took:?}"
        );
    }

    #[test]
    #[serial]
    fn test_a_kadmin_cpw_is_held_to_the_minimum_of_the_users_ou() {
        use lldap_domain_handlers::enforcement::PolicyCache;
        use lldap_domain_handlers::password::PASSWORD_MIN_LENGTH_ITEM;
        use lldap_domain_handlers::policies::CreatePolicyRequest;
        const SHORT_12: &str = "PASS_Q_TOOSHORT: the password is shorter than 12 characters";
        let memory = |runtime: &Runtime| sqlite_one_connection("sqlite::memory:", runtime);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let (runtime, temp, committer, _pool, handler, host, store, embedded) =
            wired_realm_with(&memory, &["dora"], Some(cache), None);
        runtime
            .block_on(synced(&embedded, &UserId::new("dora"), "Dora-Password-0"))
            .unwrap();
        let etypes: Vec<krb5_crypto::KeySalt> = temp
            .settings
            .supported_enctypes
            .iter()
            .map(|&e| e.into())
            .collect();
        let dora = name("dora");
        let cpw = |password: &'static str| {
            let fill = with_password(password, 0);
            let intent = intent_of(Operation::ChangePassword, kadmin(false), &["dora"], &fill);
            let edit = |s: &mut krb5_kdc::PrincipalStore| {
                let bytes = password.as_bytes();
                s.set_password_etypes_keepold_n_in(&dora, "EXAMPLE.COM", bytes, 0, ADMIN, &etypes)
            };
            match kadmin_try(&store, true, intent, &dora, &edit) {
                Ok(()) => "written".to_owned(),
                Err(StoreError::Host(KerberosStoreError::Denied(denial))) => {
                    format!("{}: {}", code_name(denial.kadm5_code), denial.text)
                }
                Err(e) => e.to_string(),
            }
        };
        let without = cpw("Dora-Pw8");
        let request = CreatePolicyRequest {
            name: "min 12".to_owned(),
            description: String::new(),
            items: std::collections::BTreeMap::from([(
                PASSWORD_MIN_LENGTH_ITEM.to_owned(),
                "12".to_owned(),
            )]),
        };
        runtime.block_on(async {
            let id = handler.create_policy(request).await.unwrap();
            handler.set_ou_policy("people", id).await.unwrap();
        });
        let with = [cpw("Dora-Pass-1"), cpw("Dora-Pass-12"), cpw("Dora-Pw8")];
        assert_eq!(
            (without, with),
            (
                "written".to_owned(),
                [
                    SHORT_12.to_owned(),
                    "written".to_owned(),
                    SHORT_12.to_owned()
                ]
            ),
            "no policy: the default 8; the OU people at 12: 11 refused, 12 written, 8 refused"
        );
        drop((embedded, store, host, temp));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_a_kadmin_cpw_reads_a_raised_minimum_though_the_cache_holds_the_old_one() {
        use lldap_domain_handlers::enforcement::{PolicyCache, fill_policy_cache};
        use lldap_domain_handlers::password::PASSWORD_MIN_LENGTH_ITEM;
        use lldap_domain_handlers::policies::{CreatePolicyRequest, UpdatePolicyRequest};
        const FIFTEEN: &str = "Dora-Pass-15chr";
        const SIXTEEN: &str = "Dora-Pass-16char";
        let memory = |runtime: &Runtime| sqlite_one_connection("sqlite::memory:", runtime);
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let (runtime, temp, committer, _pool, handler, host, store, embedded) =
            wired_realm_with(&memory, &["dora"], Some(cache), None);
        runtime
            .block_on(synced(&embedded, &UserId::new("dora"), "Dora-Password-0"))
            .unwrap();
        let etypes: Vec<krb5_crypto::KeySalt> = temp
            .settings
            .supported_enctypes
            .iter()
            .map(|&e| e.into())
            .collect();
        let dora = name("dora");
        let cpw = |password: &'static str| {
            let fill = with_password(password, 0);
            let intent = intent_of(Operation::ChangePassword, kadmin(false), &["dora"], &fill);
            let edit = |s: &mut krb5_kdc::PrincipalStore| {
                let bytes = password.as_bytes();
                s.set_password_etypes_keepold_n_in(&dora, "EXAMPLE.COM", bytes, 0, ADMIN, &etypes)
            };
            match kadmin_try(&store, true, intent, &dora, &edit) {
                Ok(()) => "written".to_owned(),
                Err(StoreError::Host(KerberosStoreError::Denied(denial))) => {
                    format!("{}: {}", code_name(denial.kadm5_code), denial.text)
                }
                Err(e) => e.to_string(),
            }
        };
        let min = |value: &str| {
            let key = PASSWORD_MIN_LENGTH_ITEM.to_owned();
            std::collections::BTreeMap::from([(key, value.to_owned())])
        };
        let held = || -> Option<String> {
            let entries = cache.get();
            let items = entries.items_of(&UserId::new("dora"))?;
            let item = items
                .iter()
                .find(|item| item.key == PASSWORD_MIN_LENGTH_ITEM)?;
            Some(item.value.clone())
        };
        let filled = runtime.block_on(async {
            let request = CreatePolicyRequest {
                name: "min 12".to_owned(),
                description: String::new(),
                items: min("12"),
            };
            let id = handler.create_policy(request).await.unwrap();
            handler.set_ou_policy("people", id).await.unwrap();
            fill_policy_cache(&handler, cache).await.unwrap();
            let filled = held();
            let raise = UpdatePolicyRequest {
                id,
                name: None,
                description: None,
                items: Some(min("16")),
            };
            handler.update_policy(raise).await.unwrap();
            filled
        });
        let before = held();
        let answers = [cpw(FIFTEEN), cpw(SIXTEEN)];
        assert_eq!(
            (
                (FIFTEEN.chars().count(), SIXTEEN.chars().count()),
                (filled, before),
                answers
            ),
            (
                (15, 16),
                (Some("12".to_owned()), Some("12".to_owned())),
                [
                    "PASS_Q_TOOSHORT: the password is shorter than 16 characters".to_owned(),
                    "written".to_owned()
                ]
            ),
            "the cache holds 12 and no fill follows the raise; kadmind's prepare reads 16"
        );
        drop((embedded, store, host, temp));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_the_commit_judges_the_minimum_its_prepare_read() {
        use lldap_test_utils::recording_log::LogGuard;
        let guard = LogGuard::install();
        let realm = SqlRealm::new(Arc::new(Nothing)).serving("EXAMPLE.COM", None);
        realm.start_pass_committed();
        let dora = krb5_kdc::PrincipalBuilder::new(name("dora"), "EXAMPLE.COM").build();
        let change = |password: &'static str, min: usize| {
            let prepared: HostPrepared = Box::new(PreparedRecord {
                user: UserId::new("dora"),
                record: Vec::new(),
                min,
            });
            let fill = with_password(password, 0);
            HostChange {
                intent: intent_of(Operation::ChangePassword, kadmin(false), &["dora"], &fill),
                rows: vec![RowChange {
                    id: "dora@EXAMPLE.COM".to_owned(),
                    before: Some(dora.clone()),
                    after: Some(dora.clone()),
                    mask: 0,
                    host_owned: true,
                }],
                prepared: Some(prepared),
                batch: RealmBatch::default(),
            }
        };
        let too_short = |n: usize| {
            let text = format!("the password is shorter than {n} characters");
            let row = denial("dora@EXAMPLE.COM", "change_password", "PASS_Q_TOOSHORT");
            (("PASS_Q_TOOSHORT".to_owned(), text), row)
        };
        let written = (
            (
                "refused".to_owned(),
                "this Kerberos store writes no directory rows".to_owned(),
            ),
            Vec::new(),
        );
        let rows = [
            (
                "11 characters, 12 at prepare",
                "Dora-Pass-1",
                12,
                too_short(12),
            ),
            (
                "12 characters, 20 at prepare",
                "Dora-Pass-12",
                20,
                too_short(20),
            ),
            (
                "12 characters, 12 at prepare: on to the write",
                "Dora-Pass-12",
                12,
                written,
            ),
        ];
        for (label, password, min, expected) in rows {
            let got = match realm.commit_change(change(password, min)) {
                Err(KerberosStoreError::Denied(denial)) => {
                    (code_name(denial.kadm5_code).to_owned(), denial.text)
                }
                Err(KerberosStoreError::Refused(why)) => ("refused".to_owned(), why),
                other => ("another answer".to_owned(), format!("{other:?}")),
            };
            let denials: Rows = guard
                .recorder()
                .take_events()
                .into_iter()
                .filter(|e| e.kind == LogKind::AccessDenied)
                .map(|e| (e.kind, e.target, e.detail))
                .collect();
            assert_eq!((got, denials), expected, "{label}");
        }
    }

    fn door_races_on(connect: Reconnect) {
        use crate::embedded::tests::kinit_code;
        use lldap_domain_handlers::handler::{BindRequest, LoginHandler, UserBackendHandler};
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{
            PasswordChangeError, PasswordSync, change_password_everywhere, finish_plain, pause,
        };
        let (runtime, temp, committer, _pool, handler, host, store, embedded) =
            wired_realm(connect, &["carl", "dave", "erin"]);
        set_kerberos_backend(embedded.clone());
        let (carl, dave) = (UserId::new("carl"), UserId::new("dave"));
        runtime.block_on(async {
            handler.update_user(sync_request("dave", 1)).await.unwrap();
            change_password_everywhere(
                &handler,
                &dave,
                "Dave-Pass-1",
                PasswordSync::On,
                PASSWORD_MIN_LENGTH,
            )
            .await
            .unwrap();
        });
        let binds = |user: &str, password: &str| {
            let request = BindRequest {
                name: UserId::new(user),
                password: password.to_owned(),
            };
            runtime.block_on(handler.bind(request)).is_ok()
        };

        let pause::Paused { reached, resume } = pause::arm(&carl);
        let (plain, ()) = runtime.block_on(async {
            tokio::join!(
                change_password_everywhere(
                    &handler,
                    &carl,
                    "Carl-Plain-1",
                    PasswordSync::Off,
                    PASSWORD_MIN_LENGTH
                ),
                async {
                    reached.await.unwrap();
                    handler.update_user(sync_request("carl", 1)).await.unwrap();
                    let synced = PasswordSync::On;
                    change_password_everywhere(
                        &handler,
                        &carl,
                        "Carl-Synced-1",
                        synced,
                        PASSWORD_MIN_LENGTH,
                    )
                    .await
                    .unwrap();
                    resume.send(()).unwrap();
                }
            )
        });
        let carl_after = (
            plain,
            (
                binds("carl", "Carl-Synced-1"),
                binds("carl", "Carl-Plain-1"),
            ),
            kinit_code(&store, "carl", "Carl-Synced-1"),
            state(&store, "carl"),
        );

        let pause::Paused { reached, resume } = pause::arm(&dave);
        let (synced, ()) = runtime.block_on(async {
            tokio::join!(
                change_password_everywhere(
                    &handler,
                    &dave,
                    "Dave-Pass-2",
                    PasswordSync::On,
                    PASSWORD_MIN_LENGTH
                ),
                async {
                    reached.await.unwrap();
                    handler.update_user(sync_request("dave", 0)).await.unwrap();
                    resume.send(()).unwrap();
                }
            )
        });
        let dave_after = (
            synced,
            (binds("dave", "Dave-Pass-1"), binds("dave", "Dave-Pass-2")),
            state(&store, "dave"),
        );

        let erin = UserId::new("erin");
        let upload =
            lldap_opaque_handler::prepare_registration(&handler, erin.clone(), b"Erin-Web-1");
        let (_, upload) = runtime.block_on(upload).unwrap();
        let pause::Paused { reached, resume } = pause::arm(&erin);
        let (web, ()) = runtime.block_on(async {
            tokio::join!(finish_plain(&handler, &erin, upload), async {
                reached.await.unwrap();
                handler.update_user(sync_request("erin", 1)).await.unwrap();
                let synced = PasswordSync::On;
                change_password_everywhere(
                    &handler,
                    &erin,
                    "Erin-Synced-1",
                    synced,
                    PASSWORD_MIN_LENGTH,
                )
                .await
                .unwrap();
                resume.send(()).unwrap();
            })
        });
        let erin_after = (
            web.map(drop),
            (binds("erin", "Erin-Synced-1"), binds("erin", "Erin-Web-1")),
            kinit_code(&store, "erin", "Erin-Synced-1"),
            state(&store, "erin"),
        );
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        let changed = || Err(PasswordChangeError::SyncChanged);
        assert_eq!(
            (carl_after, dave_after),
            (
                (changed(), (true, false), 0, Some((true, false))),
                (changed(), (true, false), None)
            ),
            "plain read first: refused, one password in both stores; synced read first: \
             refused, the directory keeps its password and no principal is made"
        );
        assert_eq!(
            erin_after,
            (changed(), (true, false), 0, Some((true, false))),
            "the web finish's upload, held: refused once the switch is on, nothing stored"
        );
        drop((embedded, store, host, temp));
        runtime.block_on(committer.shutdown());
    }

    fn reload_follows_on(connect: Reconnect) {
        use crate::embedded::DISABLED_AT_OPEN;
        use lldap_domain_handlers::handler::UserBackendHandler;
        use lldap_domain_handlers::kerberos::{NoopKerberos, set_kerberos_backend};
        use lldap_domain_handlers::password::{PasswordSync, change_password_everywhere};
        let (runtime, temp, committer, pool, handler, host, store, embedded) =
            wired_realm(connect, &["hal"]);
        set_kerberos_backend(embedded.clone());
        let hal = UserId::new("hal");
        runtime.block_on(async {
            handler.update_user(sync_request("hal", 1)).await.unwrap();
            change_password_everywhere(
                &handler,
                &hal,
                "Hal-Pass-1",
                PasswordSync::On,
                PASSWORD_MIN_LENGTH,
            )
            .await
            .unwrap();
        });
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        sql(
            &pool,
            &runtime,
            "INSERT INTO groups (group_id, display_name, lowercase_display_name, creation_date, \
             uuid, modified_date) VALUES (7, 'lldap_disabled', 'lldap_disabled', \
             '2026-01-01 00:00:00', 'uuid-disabled', '2026-01-01 00:00:00')",
        );
        sql(
            &pool,
            &runtime,
            "INSERT INTO memberships (user_id, group_id) VALUES ('hal', 7)",
        );
        let before = state(&store, "hal");
        let earlier = sync_details(&pool, &runtime, "hal").len();
        let settled = || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while host.following.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            sync_details(&pool, &runtime, "hal").split_off(earlier)
        };
        assert!(host.load().is_ok());
        let first = settled();
        let after = state(&store, "hal");
        assert!(host.load().is_ok());
        let second = settled();
        assert_eq!(
            (before, after, first, second, state(&store, "hal")),
            (
                Some((true, false)),
                Some((true, true)),
                vec![DISABLED_AT_OPEN.to_owned()],
                vec![DISABLED_AT_OPEN.to_owned()],
                Some((true, true))
            ),
            "a reload is an opening: the marked principal follows lldap_disabled, once"
        );
        drop((embedded, store, host, temp, handler));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_a_reload_sets_each_marked_principals_status_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("reload.db").display());
        reload_follows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn only_the_holder_on(connect: Reconnect) {
        use lldap_domain_handlers::handler::{BindRequest, LoginHandler, UserBackendHandler};
        use lldap_domain_handlers::kerberos::{
            DegradedKerberos, NoopKerberos, set_kerberos_backend,
        };
        use lldap_domain_handlers::password::{
            PasswordChangeError, PasswordSync, change_password_everywhere, realm_not_ready,
        };
        use lldap_test_utils::recording_log::LogGuard;
        const DEGRADED: &str = "the Kerberos realm EXAMPLE.COM did not open: test";
        let log = LogGuard::install();
        let (runtime, temp, committer, pool, handler, host, store, embedded) =
            wired_realm(connect, &["ivy", "jon"]);
        let ivy = UserId::new("ivy");
        let change = |password: &str| {
            let plain = PasswordSync::Off;
            runtime.block_on(change_password_everywhere(
                &handler,
                &ivy,
                password,
                plain,
                PASSWORD_MIN_LENGTH,
            ))
        };
        let refusals = || {
            log.recorder()
                .take_events()
                .into_iter()
                .filter(|e| !e.success && e.target.as_deref() == Some("ivy"))
                .map(|e| e.detail.unwrap_or_default())
                .collect::<Vec<_>>()
        };
        set_kerberos_backend(embedded.clone());
        let holder = (change("Ivy-Holder-1"), refusals());

        let degraded = DegradedKerberos::new("EXAMPLE.COM".to_owned(), DEGRADED.to_owned());
        set_kerberos_backend(Arc::new(degraded));
        let degraded = (change("Ivy-Degraded-1"), refusals());

        set_kerberos_backend(embedded.clone());
        sql(
            &pool,
            &runtime,
            "UPDATE kerberos_realm SET generation = generation + 1",
        );
        let taken = runtime.block_on(handler.update_user(sync_request("jon", 1)));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while embedded.ready() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let lost = (change("Ivy-Lost-1"), refusals());
        set_kerberos_backend(Arc::new(NoopKerberos::default()));
        let binds = |password: &str| {
            let request = BindRequest {
                name: ivy.clone(),
                password: password.to_owned(),
            };
            runtime.block_on(handler.bind(request)).is_ok()
        };
        let lost_cause = match &lost.0 {
            Err(PasswordChangeError::Unavailable(text)) => text.clone(),
            other => panic!("not refused as unavailable: {other:?}"),
        };
        let refused = realm_not_ready(DEGRADED);
        assert_eq!(
            (
                holder,
                degraded,
                taken.is_err(),
                lost_cause.starts_with("the Kerberos realm was lost: the realm's generation moved"),
                lost.1.len(),
                (
                    binds("Ivy-Holder-1"),
                    binds("Ivy-Degraded-1"),
                    binds("Ivy-Lost-1")
                )
            ),
            (
                (Ok(()), Vec::new()),
                (Err(refused.clone()), vec![refused.to_string()]),
                true,
                true,
                1,
                (true, false, false)
            ),
            "the holder changes it; a degraded server and one that lost the realm write nothing"
        );
        drop((embedded, store, host, temp));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_only_the_server_holding_the_realm_changes_a_password_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-holder-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("holder.db").display());
        only_the_holder_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    fn test_a_door_and_a_sync_change_race_in_both_orders_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-doors-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("doors.db").display());
        door_races_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn on_scratch_postgres(prefix: &str, rows: fn(Reconnect)) {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            eprintln!("KLLDAP_TEST_DATABASE_URL is not a postgres URL; skipping");
            return;
        }
        let schema = format!("{prefix}_{}", std::process::id());
        let made = AtomicBool::new(false);
        rows(&|runtime| {
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
    #[serial]
    #[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
    fn test_a_door_and_a_sync_change_race_in_both_orders_on_postgres() {
        on_scratch_postgres("klldap_doors", door_races_on);
    }

    #[test]
    #[serial]
    #[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
    fn test_sync_races_on_postgres() {
        on_scratch_postgres("klldap_races", sync_races_on);
    }

    const ADMIN: &str = "admin/admin@EXAMPLE.COM";
    const UNLOCKED: (i32, usize) = (krb5_kdc::TL_LAST_ADMIN_UNLOCK, 4);

    type KadminRows = Vec<(
        LogKind,
        logging::Protocol,
        Option<String>,
        Option<String>,
        Option<String>,
    )>;

    fn modify_of(mask: u32, tl_data: &[(i32, usize)], attributes: Option<u32>) -> ModifyPrincipal {
        ModifyPrincipal {
            mask,
            fields: krb5_kdc::AdminFields {
                attributes,
                ..Default::default()
            },
            tl_data: tl_data
                .iter()
                .map(|&(ty, len)| TlData {
                    ty,
                    contents: vec![7; len],
                })
                .collect(),
            zero_fail_count: mask & kadm5_mask::FAIL_AUTH_COUNT != 0,
            ..Default::default()
        }
    }

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
        with_bytes(text.as_bytes(), keepold)
    }

    fn with_bytes(password: &'static [u8], keepold: u32) -> Fill {
        Box::new(move |intent: &mut WriteIntent| {
            intent.password = Some(Zeroizing::new(password.to_vec()));
            intent.keepold = Some(keepold);
        })
    }

    const NOT_UTF8: &[u8] = b"Bob-\xff\xfe-Password";

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

    fn sync_details(pool: &DatabaseConnection, runtime: &Runtime, user: &str) -> Vec<String> {
        let query = format!(
            "SELECT detail FROM logs WHERE kind = 'kerberos_sync' AND target = '{user}' ORDER BY id"
        );
        let statement = sea_orm::Statement::from_string(pool.get_database_backend(), query);
        runtime
            .block_on(pool.query_all(statement))
            .unwrap()
            .iter()
            .map(|row| row.try_get::<String>("", "detail").unwrap())
            .collect()
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

    fn sources(
        pool: &DatabaseConnection,
        runtime: &Runtime,
        kind: &str,
    ) -> Vec<(String, Option<String>)> {
        let query = format!("SELECT protocol, actor FROM logs WHERE kind = '{kind}' ORDER BY id");
        let statement = sea_orm::Statement::from_string(pool.get_database_backend(), query);
        runtime
            .block_on(pool.query_all(statement))
            .unwrap()
            .iter()
            .map(|row| {
                let protocol = row.try_get::<String>("", "protocol").unwrap();
                (
                    protocol,
                    row.try_get::<Option<String>>("", "actor").unwrap(),
                )
            })
            .collect()
    }

    type Rows = Vec<(LogKind, Option<String>, Option<String>)>;

    fn denial(principal: &str, operation: &str, code: &str) -> Rows {
        denial_as(principal, operation, code, "")
    }

    fn denial_as(principal: &str, operation: &str, code: &str, sent: &str) -> Rows {
        let detail = format!("kadmin {operation} on {principal} by {ADMIN}: {code}{sent}");
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
        for user in ["bob", "alice", "carol"] {
            add_user(&pool, &runtime, user);
        }
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let records = Records {
            handler: Arc::new(handler.clone()),
            policies: Arc::new(handler.clone()),
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
            .block_on(synced(&embedded, &UserId::new("bob"), "Bob-Password-1"))
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
        let record = || record_of(&pool, &runtime, "bob");
        let kvno = |n: &PrincipalName| store.read().unwrap().get_name(n).and_then(|p| p.top_kvno());
        let key_bytes = |n: &PrincipalName| -> Vec<Vec<u8>> {
            let guard = store.read().unwrap();
            let keys = guard
                .get_name(n)
                .map(|p| p.keys.clone())
                .unwrap_or_default();
            keys.iter().map(|k| k.key.as_bytes().to_vec()).collect()
        };
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
        let on_bob: [Case; 15] = [
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
                "modify -policy",
                Operation::Modify,
                &["bob"],
                mask(kadm5_mask::POLICY),
                Box::new(|s: &mut PrincipalStore| {
                    let set = AdminFields {
                        policy: Some("min12".to_owned()),
                        ..Default::default()
                    };
                    s.apply_admin_fields_in(&bob, "EXAMPLE.COM", set, ADMIN)
                }),
                "modify: PROTECT_PRINCIPAL",
            ),
            (
                "modify -clearpolicy",
                Operation::Modify,
                &["bob"],
                mask(kadm5_mask::POLICY_CLR),
                Box::new(|s: &mut PrincipalStore| {
                    let clear = AdminFields {
                        clear_policy: true,
                        ..Default::default()
                    };
                    s.apply_admin_fields_in(&bob, "EXAMPLE.COM", clear, ADMIN)
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
                "cpw not UTF-8",
                Operation::ChangePassword,
                &["bob"],
                with_bytes(NOT_UTF8, 0),
                Box::new(|s: &mut PrincipalStore| {
                    s.set_password_etypes_keepold_n_in(
                        &bob,
                        "EXAMPLE.COM",
                        NOT_UTF8,
                        0,
                        ADMIN,
                        &etypes,
                    )
                }),
                "change_password: PASS_Q_GENERIC",
            ),
            (
                "cpw with a NUL, 9 characters",
                Operation::ChangePassword,
                &["bob"],
                with_password("a\0aaaaaaa", 0),
                Box::new(|s: &mut PrincipalStore| {
                    s.set_password_etypes_keepold_n_in(
                        &bob,
                        "EXAMPLE.COM",
                        b"a\0aaaaaaa",
                        0,
                        ADMIN,
                        &etypes,
                    )
                }),
                "change_password: PASS_Q_GENERIC",
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
                let intent = intent_of(*operation, kadmin(false), requested, fill);
                let answer = kadmin_write(&store, declared, intent, &bob, &**edit);
                let unchanged = (host.load().unwrap(), record()) == held;
                got.push((*label, declared, answer, unchanged, rows()));
                let logged = denial("bob@EXAMPLE.COM", op, code);
                want.push((*label, declared, code.to_owned(), true, logged));
            }
        }
        assert_eq!(got, want, "refused on a directory user's principal");

        let (bobby, robby, carl, carol) =
            (name("bobby"), name("robby"), name("carl"), name("carol"));
        for alias in [&bobby, &robby] {
            store
                .write()
                .unwrap()
                .change_committing(committing(&*host), |s| {
                    s.create_alias_in(alias, "EXAMPLE.COM", &bob, "EXAMPLE.COM", "test")
                })
                .unwrap()
                .unwrap();
        }
        unmarked(&embedded, "carol", false);
        let cary = name("cary");
        store
            .write()
            .unwrap()
            .change_committing(committing(&*host), |s| {
                s.create_alias_in(&cary, "EXAMPLE.COM", &carol, "EXAMPLE.COM", "test")
            })
            .unwrap()
            .unwrap();
        let held = (host.load().unwrap(), record());
        let through_bobby = " (requested as bobby@EXAMPLE.COM)";
        let names: [(Case, &PrincipalName, &str, &str, &str); 10] = [
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
                "AUTH_ADD",
                "",
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
                "AUTH_ADD",
                "",
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
                "AUTH_ADD",
                "",
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
                "AUTH_ADD",
                "",
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
                "AUTH_ADD",
                "",
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
                "AUTH_ADD",
                "",
            ),
            (
                (
                    "alias onto a user with no principal",
                    Operation::CreateAlias,
                    &["carl", "alice"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.create_alias_in(&carl, "EXAMPLE.COM", &alice, "EXAMPLE.COM", ADMIN)
                    }),
                    "create_alias",
                ),
                &alice,
                "alice@EXAMPLE.COM",
                "PROTECT_PRINCIPAL",
                "",
            ),
            (
                (
                    "alias onto a case twin of a user",
                    Operation::CreateAlias,
                    &["carl", "Alice"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.create_alias_in(&carl, "EXAMPLE.COM", &twin, "EXAMPLE.COM", ADMIN)
                    }),
                    "create_alias",
                ),
                &twin,
                "Alice@EXAMPLE.COM",
                "PROTECT_PRINCIPAL",
                "",
            ),
            (
                (
                    "alias onto a user's unmarked principal",
                    Operation::CreateAlias,
                    &["carl", "carol"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.create_alias_in(&carl, "EXAMPLE.COM", &carol, "EXAMPLE.COM", ADMIN)
                    }),
                    "create_alias",
                ),
                &carol,
                "carol@EXAMPLE.COM",
                "PROTECT_PRINCIPAL",
                "",
            ),
            (
                (
                    "alias onto an alias of a user's principal",
                    Operation::CreateAlias,
                    &["carl", "bobby"],
                    nothing(),
                    Box::new(|s: &mut PrincipalStore| {
                        s.create_alias_in(&carl, "EXAMPLE.COM", &bobby, "EXAMPLE.COM", ADMIN)
                    }),
                    "create_alias",
                ),
                &bobby,
                "bob@EXAMPLE.COM",
                "PROTECT_PRINCIPAL",
                through_bobby,
            ),
        ];
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for ((label, operation, requested, fill, edit, op), peek, principal, code, sent) in &names {
            for declared in [true, false] {
                let intent = intent_of(*operation, kadmin(false), requested, fill);
                let answer = kadmin_write(&store, declared, intent, peek, &**edit);
                let unchanged = (host.load().unwrap(), record()) == held;
                got.push((*label, declared, answer, unchanged, rows()));
                let logged = denial_as(principal, op, code, sent);
                want.push((*label, declared, (*code).to_owned(), true, logged));
            }
        }
        assert_eq!(
            got, want,
            "a directory user's name, created or aliased onto"
        );

        let (bobbie, caryn) = (name("bobbie"), name("caryn"));
        let renames = [
            (
                ["bobby", "bobbie"],
                &bobby,
                &bobbie,
                &bob,
                "bob@EXAMPLE.COM",
            ),
            (
                ["cary", "caryn"],
                &cary,
                &caryn,
                &carol,
                "carol@EXAMPLE.COM",
            ),
        ];
        let unsupported = StoreError::AliasUnsupported.to_string();
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (requested, alias, renamed, target, principal) in renames {
            let rename = |s: &mut PrincipalStore| {
                s.rename_unchecked(alias, "EXAMPLE.COM", renamed, "EXAMPLE.COM", ADMIN)
            };
            let its_rows = |s: &mut PrincipalStore| -> Result<(), StoreError> {
                s.remove_in(alias, "EXAMPLE.COM")?;
                s.create_alias_in(renamed, "EXAMPLE.COM", target, "EXAMPLE.COM", ADMIN)
            };
            let sent = format!(" (requested as {}@EXAMPLE.COM)", requested[0]);
            let protect = denial_as(principal, "rename", "PROTECT_PRINCIPAL", &sent);
            type Write<'a> = &'a dyn Fn(&mut PrincipalStore) -> Result<(), StoreError>;
            let runs: [(bool, Write, &str, Rows); 3] = [
                (true, &rename, "PROTECT_PRINCIPAL", protect.clone()),
                (false, &rename, &unsupported, Vec::new()),
                (false, &its_rows, "PROTECT_PRINCIPAL", protect),
            ];
            for (declared, edit, answer, logged) in runs {
                let intent = intent_of(Operation::Rename, kadmin(false), &requested, &nothing());
                let answered = kadmin_write(&store, declared, intent, alias, edit);
                let unchanged = (host.load().unwrap(), record()) == held;
                got.push((requested[0], declared, answered, unchanged, rows()));
                want.push((requested[0], declared, answer.to_owned(), true, logged));
            }
        }
        assert_eq!(
            got, want,
            "renaming an alias of a directory user's principal: with prepare, without, and its rows"
        );

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
        let kadmin_from = |client: &str| ("kadmin".to_owned(), Some(client.to_owned()));
        let not_prepared = denial(
            "bob@EXAMPLE.COM",
            "change_password",
            "PASS_Q_GENERIC: the change could not be prepared",
        );
        assert_eq!(
            (
                got,
                details(&pool, &runtime, "password_change"),
                sources(&pool, &runtime, "password_change")
            ),
            (
                vec![
                    done("an admin's cpw"),
                    done("a self-service cpw"),
                    (
                        "a cpw kadmind did not prepare",
                        "PASS_Q_GENERIC".to_owned(),
                        (false, false),
                        false,
                        not_prepared
                    ),
                ],
                vec![by_admin, by_bob],
                vec![kadmin_from(ADMIN), kadmin_from("bob@EXAMPLE.COM")],
            ),
            "carried out: the keys, the record and one row; a cpw kadmind did not prepare: refused"
        );

        let own_purge = |declared: bool| {
            let intent = intent_of(Operation::PurgeKeys, kadmin(true), &["bob"], &nothing());
            let edit = |s: &mut PrincipalStore| s.purgekeys_in(&bob, "EXAMPLE.COM", 0, ADMIN);
            kadmin_write(&store, declared, intent, &bob, &edit)
        };
        let answers = [own_purge(true), own_purge(false)];
        let keyed: Vec<_> = guard
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.kind == LogKind::AccessDenied)
            .map(|e| (e.protocol, e.actor, e.target))
            .collect();
        let bob_at = Some("bob@EXAMPLE.COM".to_owned());
        let refused = "PROTECT_PRINCIPAL".to_owned();
        assert_eq!(
            (answers, keyed),
            (
                [refused.clone(), refused],
                vec![(logging::Protocol::Kadmin, bob_at.clone(), bob_at); 2]
            ),
            "a user's own refusal: actor and target are one string, the coalescer's key"
        );

        let cpw_through = |text: &'static str, keepold: u32, declared: bool| {
            let fill = with_password(text, keepold);
            let intent = intent_of(Operation::ChangePassword, kadmin(false), &["bobby"], &fill);
            let edit = |s: &mut PrincipalStore| {
                let password = text.as_bytes();
                s.set_password_etypes_keepold_n_in(
                    &bobby,
                    "EXAMPLE.COM",
                    password,
                    keepold,
                    ADMIN,
                    &etypes,
                )
            };
            kadmin_write(&store, declared, intent, &bobby, &edit)
        };
        let (before, stored) = (kvno(&bob), record());
        let changed = cpw_through("Bob-Password-6", 0, true);
        let both = (kvno(&bob) == before.map(|k| k + 1), record() != stored);
        let carried = (changed, both, binds("Bob-Password-6"), rows());
        let refused: Vec<_> = [true, false]
            .into_iter()
            .map(|declared| (cpw_through("Bob-Password-8", 1, declared), rows()))
            .collect();
        let keepold = denial_as(
            "bob@EXAMPLE.COM",
            "change_password",
            "PROTECT_PRINCIPAL",
            through_bobby,
        );
        let protect = ("PROTECT_PRINCIPAL".to_owned(), keepold);
        assert_eq!(
            (
                carried,
                refused,
                details(&pool, &runtime, "password_change").last().cloned()
            ),
            (
                ("written".to_owned(), (true, true), true, Vec::new()),
                vec![protect.clone(), protect],
                Some(format!("kadmin change_password by {ADMIN}{through_bobby}"))
            ),
            "a cpw through an alias, carried out and refused: both names"
        );

        let deleted: Vec<_> = [(&robby, "robby", true), (&bobby, "bobby", false)]
            .into_iter()
            .map(|(alias, text, declared)| {
                let intent = intent_of(Operation::Delete, kadmin(false), &[text], &nothing());
                let edit = |s: &mut PrincipalStore| s.remove_in(alias, "EXAMPLE.COM");
                let (keys, stored) = (key_bytes(&bob), record());
                let got = kadmin_write(&store, declared, intent, alias, &edit);
                let raw = format!("{text}@EXAMPLE.COM");
                let gone = store.read().unwrap().get_raw(&raw).is_none();
                let kept = key_bytes(&bob) == keys && record() == stored;
                (got, gone, kept, rows())
            })
            .collect();
        assert_eq!(
            deleted,
            vec![("written".to_owned(), true, true, Vec::new()); 2],
            "an alias of a directory user's principal is deleted, with and without prepare"
        );

        let unlock = intent_of(
            Operation::Modify,
            kadmin(false),
            &["bob"],
            &mask(kadm5_mask::FAIL_AUTH_COUNT),
        );
        let edit = |s: &mut PrincipalStore| s.clear_fail_auth_count_in(&bob, "EXAMPLE.COM", ADMIN);
        let (keys_unlocked, stored) = (key_bytes(&bob), record());
        let unlocked = kadmin_write(&store, true, unlock, &bob, &edit);
        let unlock_row = format!("kadmin unlock by {ADMIN}");
        assert_eq!(
            (
                unlocked,
                rows(),
                key_bytes(&bob) == keys_unlocked,
                record() == stored
            ),
            (
                "written".to_owned(),
                vec![(
                    LogKind::KerberosSync,
                    Some("bob@EXAMPLE.COM".to_owned()),
                    Some(unlock_row)
                )],
                true,
                true
            ),
            "unlocked: the keys and the record unchanged"
        );

        let one_bit = kadm5_mask::FAIL_AUTH_COUNT;
        let mit = one_bit | kadm5_mask::TL_DATA;
        let with_attribute = mit | kadm5_mask::ATTRIBUTES;
        let flipped = store.read().unwrap().get_name(&bob).map(|p| p.attributes);
        let flipped = flipped.map(|a| a ^ krb5_kdc::KDB_DISALLOW_POSTDATED);
        let unlocks: [(&str, u32, ModifyPrincipal, bool); 6] = [
            ("MIT's unlock", mit, modify_of(mit, &[UNLOCKED], None), true),
            (
                "the one-bit unlock",
                one_bit,
                modify_of(one_bit, &[], None),
                true,
            ),
            (
                "an unlock with a second TL entry",
                mit,
                modify_of(mit, &[UNLOCKED, (0x0701, 4)], None),
                false,
            ),
            (
                "an unlock with one TL entry of another type",
                mit,
                modify_of(mit, &[(0x0701, 4)], None),
                false,
            ),
            (
                "an unlock with an attribute",
                with_attribute,
                modify_of(with_attribute, &[UNLOCKED], flipped),
                false,
            ),
            (
                "an unlock whose mask hides an attribute",
                mit,
                modify_of(with_attribute, &[UNLOCKED], flipped),
                false,
            ),
        ];
        let in_memory = || {
            let read = store.read().unwrap();
            let p = read.get_name(&bob).unwrap();
            (p.tl_data.clone(), p.attributes, p.fail_auth_count)
        };
        let kadmin_rows = || -> KadminRows {
            let events = guard.recorder().take_events().into_iter();
            events
                .filter(|e| e.kind != LogKind::Bind)
                .map(|e| (e.kind, e.protocol, e.actor, e.target, e.detail))
                .collect()
        };
        let kadmin_row = |kind: LogKind, detail: &str| {
            let target = Some("bob@EXAMPLE.COM".to_owned());
            let admin = Some(ADMIN.to_owned());
            let protocol = logging::Protocol::Kadmin;
            (kind, protocol, admin, target, Some(detail.to_owned()))
        };
        let unlocked_row = format!("kadmin unlock by {ADMIN}");
        let refused_row = format!("kadmin modify on bob@EXAMPLE.COM by {ADMIN}: PROTECT_PRINCIPAL");
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (label, client_mask, modify, carried) in &unlocks {
            for declared in [true, false] {
                let intent = intent_of(
                    Operation::Modify,
                    kadmin(false),
                    &["bob"],
                    &mask(*client_mask),
                );
                let edit = |s: &mut PrincipalStore| {
                    s.modify_principal_in(&bob, "EXAMPLE.COM", modify.clone(), ADMIN)
                };
                let held = (host.load().unwrap(), record(), in_memory());
                let (keys, stored) = (key_bytes(&bob), record());
                let answer = kadmin_write(&store, declared, intent, &bob, &edit);
                let (tl_data, _, fail_auth_count) = in_memory();
                let entries: Vec<usize> = tl_data
                    .iter()
                    .filter(|tl| tl.ty == TL_LAST_ADMIN_UNLOCK)
                    .map(|tl| tl.contents.len())
                    .collect();
                let kept = (key_bytes(&bob) == keys, record() == stored);
                let unchanged = (host.load().unwrap(), record(), in_memory()) == held;
                let unchanged = (!carried).then_some(unchanged);
                let outcome = (kept, unchanged, fail_auth_count, entries);
                got.push((*label, declared, answer, outcome, kadmin_rows()));
                let (answer, row) = if *carried {
                    ("written", kadmin_row(LogKind::KerberosSync, &unlocked_row))
                } else {
                    (
                        "PROTECT_PRINCIPAL",
                        kadmin_row(LogKind::AccessDenied, &refused_row),
                    )
                };
                let outcome = ((true, true), (!carried).then_some(true), 0, vec![4]);
                want.push((*label, declared, answer.to_owned(), outcome, vec![row]));
            }
        }
        assert_eq!(
            got, want,
            "unlocks: MIT's and the one-bit form are carried out, any other change is refused"
        );

        let mark = |owned: bool| {
            store
                .write()
                .unwrap()
                .change_committing(committing(&*host), |s| {
                    s.set_host_owned_in(&bob, "EXAMPLE.COM", owned)
                })
                .unwrap()
                .unwrap();
        };
        let fill = with_password("Bob-Password-7", 0);
        let intent = intent_of(Operation::ChangePassword, kadmin(false), &["bob"], &fill);
        let (intent, prepared) =
            krb5_kdc::declare_shared(&store, Some((&bob, "EXAMPLE.COM")), |_| intent).unwrap();
        let was_prepared = prepared.is_some();
        mark(false);
        let (before, stored, logged) = (
            kvno(&bob),
            record(),
            details(&pool, &runtime, "password_change"),
        );
        let cleared = answer(store.write().unwrap().change_as(intent, prepared, |s| {
            let password = b"Bob-Password-7";
            s.set_password_etypes_keepold_n_in(&bob, "EXAMPLE.COM", password, 0, ADMIN, &etypes)
        }));
        let after_cleared = (
            was_prepared,
            cleared,
            kvno(&bob) == before.map(|k| k + 1),
            record() == stored,
            details(&pool, &runtime, "password_change") == logged,
            rows(),
        );
        let intent = intent_of(Operation::Randkey, kadmin(false), &["bob"], &nothing());
        let (intent, prepared) =
            krb5_kdc::declare_shared(&store, Some((&bob, "EXAMPLE.COM")), |_| intent).unwrap();
        let passed = prepared.is_none() && rows().is_empty();
        mark(true);
        let (keys_before, stored) = (key_bytes(&bob), record());
        let set = answer(store.write().unwrap().change_as(intent, prepared, |s| {
            s.chrand_etypes_keepold_in(&bob, "EXAMPLE.COM", &etypes, 0, ADMIN)
                .map(drop)
        }));
        let after_set = (
            passed,
            set,
            key_bytes(&bob) == keys_before && record() == stored,
            rows(),
        );
        assert_eq!(
            (after_cleared, after_set),
            (
                (true, "written", true, true, true, Vec::new()),
                (
                    true,
                    "denied",
                    true,
                    denial("bob@EXAMPLE.COM", "randkey", "PROTECT_PRINCIPAL")
                )
            ),
            "the mark changed between prepare and the commit: the commit's answer stands"
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
                binds("Bob-Password-6"),
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

    /// `Records`' deriver, counting each registration it starts.
    fn counting_deriver(calls: Arc<AtomicUsize>) -> Arc<dyn OpaqueHandler> {
        use lldap_auth::opaque::server::{generate_random_private_key, registration};
        let setup = generate_random_private_key();
        let mut deriver = lldap_test_utils::MockTestBackendHandler::new();
        deriver
            .expect_registration_start()
            .returning(move |request| {
                calls.fetch_add(1, Ordering::SeqCst);
                let start = registration::start_registration(
                    &setup,
                    request.registration_start_request,
                    &request.username,
                )?;
                Ok(
                    lldap_opaque_handler::registration::ServerRegistrationStartResponse {
                        server_data: String::new(),
                        registration_response: start.message,
                    },
                )
            });
        Arc::new(deriver)
    }

    fn unprepared_rows_on(connect: Reconnect) {
        use krb5_kdc::PrincipalStore;
        use lldap_test_utils::recording_log::LogGuard;

        let guard = LogGuard::install();
        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let (committer, pool) = committer_on(connect, &runtime);
        for user in ["bob", "alice"] {
            add_user(&pool, &runtime, user);
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let (policies, _) = minimums(&[Some(PASSWORD_MIN_LENGTH)]);
        let records = Records {
            handler: counting_deriver(Arc::clone(&calls)),
            policies,
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
            .block_on(synced(&embedded, &UserId::new("bob"), "Bob-Password-1"))
            .unwrap();
        let bob = name("bob");
        let etypes: Vec<krb5_crypto::KeySalt> = temp
            .settings
            .supported_enctypes
            .iter()
            .map(|&e| e.into())
            .collect();
        let kvno = || {
            store
                .read()
                .unwrap()
                .get_name(&bob)
                .and_then(|p| p.top_kvno())
        };
        let keys = || -> Vec<Vec<u8>> {
            let read = store.read().unwrap();
            let keys = &read.get_name(&bob).unwrap().keys;
            keys.iter().map(|k| k.key.as_bytes().to_vec()).collect()
        };
        let rows = || -> Rows {
            let events = guard.recorder().take_events().into_iter();
            events.map(|e| (e.kind, e.target, e.detail)).collect()
        };
        rows();

        type Token<'a> = &'a dyn Fn(WriteIntent) -> (WriteIntent, Option<HostPrepared>);
        let none = |intent: WriteIntent| (intent, None::<HostPrepared>);
        let another_type = |intent: WriteIntent| (intent, Some(Box::new(7_u32) as HostPrepared));
        let alices = |intent: WriteIntent| {
            let alice = PreparedRecord {
                user: UserId::new("alice"),
                record: b"alice's record".to_vec(),
                min: PASSWORD_MIN_LENGTH,
            };
            (intent, Some(Box::new(alice) as HostPrepared))
        };
        let declared = |intent: WriteIntent| {
            krb5_kdc::declare_shared(&store, Some((&bob, "EXAMPLE.COM")), |_| intent).unwrap()
        };
        let runs: [(&'static str, &'static str, Token); 4] = [
            ("no prepared change", "Bob-Password-2", &none),
            (
                "a prepared change of another type",
                "Bob-Password-3",
                &another_type,
            ),
            ("another user's prepared change", "Bob-Password-4", &alices),
            ("its own prepared change", "Bob-Password-5", &declared),
        ];
        let warnings = Warnings::default();
        let mut got = Vec::new();
        for (label, text, token) in runs {
            let fill = with_password(text, 0);
            let intent = intent_of(Operation::ChangePassword, kadmin(false), &["bob"], &fill);
            let (intent, prepared) = token(intent);
            let held = keys();
            let edit = |s: &mut PrincipalStore| {
                let password = text.as_bytes();
                s.set_password_etypes_keepold_n_in(&bob, "EXAMPLE.COM", password, 0, ADMIN, &etypes)
            };
            let done = tracing::subscriber::with_default(warnings.clone(), || {
                store.write().unwrap().change_as(intent, prepared, edit)
            });
            let answer = match done.and_then(|done| done) {
                Ok(()) => "written".to_owned(),
                Err(StoreError::Host(KerberosStoreError::Denied(d))) => {
                    format!("{}: {}", code_name(d.kadm5_code), d.text)
                }
                Err(e) => e.to_string(),
            };
            let warned: Vec<String> = std::mem::take(&mut *warnings.0.lock().unwrap())
                .into_iter()
                .filter(|line| line.starts_with("kadmin "))
                .collect();
            let record = record_of(&pool, &runtime, "bob").is_some();
            let state = (kvno(), keys() == held, record);
            got.push((
                label,
                answer,
                calls.load(Ordering::SeqCst),
                state,
                rows(),
                warned,
            ));
        }
        let refused = |label: &'static str| {
            (
                label,
                "PASS_Q_GENERIC: the change could not be prepared; try again".to_owned(),
                0,
                (Some(1), true, false),
                vec![(
                    LogKind::AccessDenied,
                    Some("bob@EXAMPLE.COM".to_owned()),
                    Some(
                        "kadmin change_password on bob@EXAMPLE.COM by admin/admin@EXAMPLE.COM: \
                         PASS_Q_GENERIC: the change could not be prepared"
                            .to_owned(),
                    ),
                )],
                vec![
                    "kadmin change_password for bob: kadmind's commit came without its \
                     prepared change and is refused, so nothing is derived under the store's lock"
                        .to_owned(),
                ],
            )
        };
        assert_eq!(
            (got, details(&pool, &runtime, "password_change")),
            (
                vec![
                    refused("no prepared change"),
                    refused("a prepared change of another type"),
                    refused("another user's prepared change"),
                    (
                        "its own prepared change",
                        "written".to_owned(),
                        1,
                        (Some(2), false, true),
                        Vec::new(),
                        Vec::new()
                    ),
                ],
                vec!["kadmin change_password by admin/admin@EXAMPLE.COM".to_owned()],
            ),
            "a cpw commit without its own prepared change: refused, nothing derived or written"
        );
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_a_cpw_kadmind_did_not_prepare_is_refused_before_anything_is_derived_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-unprepared-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("k1.db").display());
        unprepared_rows_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    const OTHER_REALM_CHILD: &str = "seam::tests::child_kadmind_answers_for_the_served_realm";
    const OTHER_REALM_DONE: &str = "kadmind answered for EXAMPLE.COM";
    const KADM5_API_V2: u32 = 0x1234_5702;
    const CREATE_PRINCIPAL: u32 = 1;
    const CHPASS_PRINCIPAL: u32 = 6;
    const CHPASS_PRINCIPAL3: u32 = 19;
    const RPG_DATA: u32 = 0;
    const RPG_INIT: u32 = 1;
    const GSS_INTEGRITY: u32 = 2;
    const FLAVOR_GSS: u32 = 6;

    fn xdr(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_be_bytes()).collect()
    }

    fn opaque(bytes: &[u8]) -> Vec<u8> {
        let mut v = xdr(&[u32::try_from(bytes.len()).unwrap()]);
        v.extend_from_slice(bytes);
        v.resize(v.len() + (4 - bytes.len() % 4) % 4, 0);
        v
    }

    fn c_string(text: &str) -> Vec<u8> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        opaque(&bytes)
    }

    struct Words<'a>(&'a [u8]);

    impl Words<'_> {
        fn u32(&mut self) -> u32 {
            let (word, rest) = self.0.split_at(4);
            self.0 = rest;
            u32::from_be_bytes(word.try_into().unwrap())
        }

        fn opaque(&mut self) -> Vec<u8> {
            let n = usize::try_from(self.u32()).unwrap();
            let bytes = self.0[..n].to_vec();
            self.0 = &self.0[n + (4 - n % 4) % 4..];
            bytes
        }
    }

    fn rpc_header(xid: u32, proc: u32, cred: &[u8]) -> Vec<u8> {
        [xdr(&[xid, 0, 2, 2112, 2, proc, FLAVOR_GSS]), opaque(cred)].concat()
    }

    fn rpcsec(gss_proc: u32, seq: u32, handle: &[u8]) -> Vec<u8> {
        [xdr(&[1, gss_proc, seq, GSS_INTEGRITY]), opaque(handle)].concat()
    }

    fn exchange(stream: &mut std::net::TcpStream, call: &[u8]) -> Vec<u8> {
        use std::io::{Read, Write};
        let mark = u32::try_from(call.len()).unwrap() | 0x8000_0000;
        stream
            .write_all(&[&mark.to_be_bytes()[..], call].concat())
            .unwrap();
        let mut mark = [0; 4];
        stream.read_exact(&mut mark).unwrap();
        let length = u32::from_be_bytes(mark) & 0x7fff_ffff;
        let mut reply = vec![0; usize::try_from(length).unwrap()];
        stream.read_exact(&mut reply).unwrap();
        reply
    }

    /// The name goes on the wire as written: "bob" carries no realm.
    fn kadm5_args(proc: u32, name: &str, password: &str) -> Vec<u8> {
        let fields = match proc {
            CREATE_PRINCIPAL => vec![
                0, 0, 0, 3600, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
            ],
            CHPASS_PRINCIPAL3 => vec![1, 0],
            _ => Vec::new(),
        };
        let head = [xdr(&[KADM5_API_V2]), c_string(name), xdr(&fields)].concat();
        [head, c_string(password)].concat()
    }

    /// A kadmin session over kadmind's TCP socket: RPCSEC_GSS with integrity, kadm5 API v2.
    struct Kadm5Wire {
        stream: std::net::TcpStream,
        gss: krb5_gss::GssContext,
        handle: Vec<u8>,
        seq: u32,
    }

    impl Kadm5Wire {
        fn open(
            kadmind: std::net::SocketAddr,
            store: &krb5_kdc::SharedDump,
            client: &PrincipalName,
            key: &krb5_crypto::ProtocolKey,
        ) -> Self {
            let etypes = vec![krb5_crypto::EncryptionType::Aes256CtsHmacSha196.to_iana()];
            let padata = vec![krb5_protocol::pa_enc_timestamp(key).unwrap()];
            let service = krb5_kdc::principals::kadmin_admin();
            let request = krb5_protocol::as_req_sname(
                client.clone(),
                "EXAMPLE.COM",
                7,
                Some(padata),
                service,
                etypes,
            )
            .unwrap();
            let issued = krb5_kdc::issue_as(&*store.read().unwrap(), &request).unwrap();
            let now = krb5_types::KerberosTime::now();
            let times = krb5_protocol::TicketTimes {
                authtime: now.clone(),
                starttime: None,
                endtime: now.add_hours(1).unwrap(),
            };
            let (mut gss, token) = krb5_gss::GssContext::init_sec_context(
                issued.rep.0.ticket.clone(),
                &issued.session_key,
                &krb5_types::ascii("EXAMPLE.COM"),
                client,
                krb5_gss::GSS_C_MUTUAL | krb5_gss::GSS_C_SEQUENCE,
                None,
                None,
                None,
                0,
                &times,
            )
            .unwrap();
            let mut stream = std::net::TcpStream::connect(kadmind).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let init = rpc_header(1, 0, &rpcsec(RPG_INIT, 0, &[]));
            let reply = exchange(&mut stream, &[init, xdr(&[0, 0]), opaque(&token)].concat());
            let mut r = Words(&reply);
            assert_eq!([r.u32(), r.u32(), r.u32(), r.u32()], [1, 1, 0, FLAVOR_GSS]);
            let verf = r.opaque();
            assert_eq!(r.u32(), 0, "the context is accepted");
            let handle = r.opaque();
            let (_major, _minor, window) = (r.u32(), r.u32(), r.u32());
            gss.process_ap_rep(&r.opaque(), &issued.session_key)
                .unwrap();
            gss.verify_mic(&window.to_be_bytes(), &verf).unwrap();
            Self {
                stream,
                gss,
                handle,
                seq: 0,
            }
        }

        fn call(&mut self, proc: u32, args: &[u8]) -> u32 {
            self.seq += 1;
            let xid = self.seq + 1;
            let header = rpc_header(xid, proc, &rpcsec(RPG_DATA, self.seq, &self.handle));
            let body = [&self.seq.to_be_bytes()[..], args].concat();
            let verf = self.gss.get_mic(&header).unwrap();
            let checksum = self.gss.get_mic(&body).unwrap();
            let signed = [opaque(&verf), opaque(&body), opaque(&checksum)].concat();
            let call = [header, xdr(&[FLAVOR_GSS]), signed].concat();
            let reply = exchange(&mut self.stream, &call);
            let mut r = Words(&reply);
            assert_eq!(
                [r.u32(), r.u32(), r.u32(), r.u32()],
                [xid, 1, 0, FLAVOR_GSS]
            );
            let verf = r.opaque();
            assert_eq!(r.u32(), 0, "the call is accepted");
            self.gss.verify_mic(&self.seq.to_be_bytes(), &verf).unwrap();
            let (body, checksum) = (r.opaque(), r.opaque());
            self.gss.verify_mic(&body, &checksum).unwrap();
            let mut r = Words(&body);
            assert_eq!([r.u32(), r.u32()], [self.seq, KADM5_API_V2]);
            r.u32()
        }
    }

    type PasswordRow = (Option<String>, String, Option<String>, String);

    fn password_rows(pool: &DatabaseConnection, runtime: &Runtime) -> Vec<PasswordRow> {
        let query = "SELECT target, protocol, actor, detail FROM logs \
                     WHERE kind = 'password_change' ORDER BY id";
        let statement = sea_orm::Statement::from_string(pool.get_database_backend(), query);
        runtime
            .block_on(pool.query_all(statement))
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row.try_get::<Option<String>>("", "target").unwrap(),
                    row.try_get::<String>("", "protocol").unwrap(),
                    row.try_get::<Option<String>>("", "actor").unwrap(),
                    row.try_get::<String>("", "detail").unwrap(),
                )
            })
            .collect()
    }

    #[test]
    #[serial]
    #[ignore = "a child process of test_kadmin_writes_land_in_the_served_realm_whatever_krb5_conf_names"]
    fn child_kadmind_answers_for_the_served_realm() {
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain_handlers::handler::{BindRequest, LoginHandler};
        use lldap_sql_backend_handler::SqlBackendHandler;
        use lldap_test_utils::recording_log::LogGuard;

        let named = krb5_config::load_krb5_conf().and_then(|conf| conf.default_realm);
        if named.as_deref() != Some("OTHER.TEST") {
            eprintln!("KRB5_CONFIG names {named:?}, not OTHER.TEST: only the parent row runs this");
            return;
        }
        let guard = LogGuard::install();
        let runtime = runtime();
        let temp = TempRealm::new();
        assert_eq!(
            boot::profile(&temp.settings).krb5.default_realm.as_deref(),
            Some("EXAMPLE.COM"),
            "the composed profile names the served realm, the process's krb5.conf another"
        );
        let dir = std::env::temp_dir().join(format!("klldap-other-realm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("other-realm.db").display());
        let connect = |runtime: &Runtime| sqlite_one_connection(&url, runtime);
        let (committer, pool) = committer_on(&connect, &runtime);
        for user in ["bob", "alice"] {
            add_user(&pool, &runtime, user);
        }
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let records = Records {
            handler: Arc::new(handler.clone()),
            policies: Arc::new(handler.clone()),
            runtime: runtime.handle().clone(),
        };
        let host = Arc::new(SqlRealm::new(committer.store()).serving("EXAMPLE.COM", Some(records)));
        let (embedded, opened) = EmbeddedKerberos::open_on(&temp.settings, host.clone()).unwrap();
        host.start_pass_committed();
        runtime
            .block_on(synced(&embedded, &UserId::new("bob"), "Bob-Password-1"))
            .unwrap();
        let (store, kadmind) = (opened.store(), opened.kadmin());
        let threads = opened.serve().unwrap();
        let (admin, bob, alice) = (boot::admin_principal(), name("bob"), name("alice"));
        let admin_key = {
            let realm = store.read().unwrap();
            realm
                .get_name(&admin)
                .unwrap()
                .best_key()
                .unwrap()
                .key
                .clone()
        };
        let bob_key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            "Bob-Password-1",
            bob.default_salt("EXAMPLE.COM"),
            None,
        )
        .unwrap();
        let mut by_admin = Kadm5Wire::open(kadmind, &store, &admin, &admin_key);
        let mut by_bob = Kadm5Wire::open(kadmind, &store, &bob, &bob_key);
        let record = || record_of(&pool, &runtime, "bob");
        let kvno = || {
            store
                .read()
                .unwrap()
                .get_name(&bob)
                .and_then(|p| p.top_kvno())
        };
        let no_alice = || store.read().unwrap().get_name(&alice).is_none();
        let binds = |user: &str, password: &str| {
            let request = BindRequest {
                name: UserId::new(user),
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
        let earlier = password_rows(&pool, &runtime).len();

        const BOB: &str = "bob@EXAMPLE.COM";
        const ALICE: &str = "alice@EXAMPLE.COM";
        type Wire = (&'static str, bool, u32, &'static str, &'static str);
        let cases: [Wire; 8] = [
            (
                "an admin's cpw",
                false,
                CHPASS_PRINCIPAL,
                BOB,
                "Bob-Password-2",
            ),
            (
                "a self-service cpw",
                true,
                CHPASS_PRINCIPAL,
                BOB,
                "Bob-Password-3",
            ),
            (
                "an admin's cpw, bare",
                false,
                CHPASS_PRINCIPAL,
                "bob",
                "Bob-Password-4",
            ),
            (
                "a self-service cpw, bare",
                true,
                CHPASS_PRINCIPAL,
                "bob",
                "Bob-Password-5",
            ),
            (
                "cpw -keepold",
                false,
                CHPASS_PRINCIPAL3,
                BOB,
                "Bob-Password-6",
            ),
            (
                "cpw -keepold, bare",
                false,
                CHPASS_PRINCIPAL3,
                "bob",
                "Bob-Password-7",
            ),
            (
                "addprinc",
                false,
                CREATE_PRINCIPAL,
                ALICE,
                "Alice-Password-1",
            ),
            (
                "addprinc, bare",
                false,
                CREATE_PRINCIPAL,
                "alice",
                "Alice-Password-2",
            ),
        ];
        let mut got = Vec::new();
        for (label, own, proc, sent, password) in cases {
            let (before, stored) = (kvno(), record());
            let client = if own { &mut by_bob } else { &mut by_admin };
            let answer = match client.call(proc, &kadm5_args(proc, sent, password)) {
                0 => "written",
                code => code_name(code),
            };
            let moved = (kvno() == before.map(|k| k + 1), record() != stored);
            let user = sent.split('@').next().unwrap();
            let doors = (binds(user, password), no_alice());
            got.push((label, answer, moved, doors, rows()));
        }
        let written = |label| (label, "written", (true, true), (true, true), Vec::new());
        let refused = |label, code, rows| (label, code, (false, false), (false, true), rows);
        let keepold = denial(BOB, "change_password", "PROTECT_PRINCIPAL");
        let add = denial(ALICE, "create", "AUTH_ADD");
        let cpw = |actor: &str, detail: String| {
            let kadmin = "kadmin".to_owned();
            (Some(BOB.to_owned()), kadmin, Some(actor.to_owned()), detail)
        };
        let by_admin_row = cpw(ADMIN, format!("kadmin change_password by {ADMIN}"));
        let by_bob_row = cpw(
            BOB,
            format!("kadmin change_password by {BOB} (self-service)"),
        );
        assert_eq!(
            (got, password_rows(&pool, &runtime).split_off(earlier)),
            (
                vec![
                    written("an admin's cpw"),
                    written("a self-service cpw"),
                    written("an admin's cpw, bare"),
                    written("a self-service cpw, bare"),
                    refused("cpw -keepold", "PROTECT_PRINCIPAL", keepold.clone()),
                    refused("cpw -keepold, bare", "PROTECT_PRINCIPAL", keepold),
                    refused("addprinc", "AUTH_ADD", add.clone()),
                    refused("addprinc, bare", "AUTH_ADD", add),
                ],
                vec![
                    by_admin_row.clone(),
                    by_bob_row.clone(),
                    by_admin_row,
                    by_bob_row
                ],
            ),
            "krb5.conf names OTHER.TEST: each kadm5 request, qualified or bare, is on EXAMPLE.COM"
        );
        drop((by_admin, by_bob));
        threads.stop();
        drop((embedded, store, host, temp));
        runtime.block_on(committer.shutdown());
        let _ = std::fs::remove_dir_all(&dir);
        println!("{OTHER_REALM_DONE}");
    }

    #[test]
    #[serial]
    fn test_kadmin_writes_land_in_the_served_realm_whatever_krb5_conf_names() {
        let dir = std::env::temp_dir().join(format!("klldap-krb5-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conf = dir.join("krb5.conf");
        std::fs::write(&conf, "[libdefaults]\n default_realm = OTHER.TEST\n").unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                OTHER_REALM_CHILD,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KRB5_CONFIG", &conf)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success()
                && stdout.contains("1 passed")
                && stdout.contains(OTHER_REALM_DONE),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    #[serial]
    fn test_a_kadmin_unlock_is_the_directorys_at_the_servers_clock_whatever_time_it_carries() {
        use krb5_kdc::PrincipalStore;
        use lldap_auth::opaque::server::generate_random_private_key;
        use lldap_domain_handlers::lockout::LockStore;
        use lldap_sql_backend_handler::SqlBackendHandler;

        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let memory = |runtime: &Runtime| sqlite_one_connection("sqlite::memory:", runtime);
        let (committer, pool) = committer_on(&memory, &runtime);
        add_user(&pool, &runtime, "e1kadmin");
        let handler = SqlBackendHandler::new(generate_random_private_key(), pool.clone());
        let records = Records {
            handler: Arc::new(handler.clone()),
            policies: Arc::new(handler.clone()),
            runtime: runtime.handle().clone(),
        };
        let host = Arc::new(SqlRealm::new(committer.store()).serving("EXAMPLE.COM", Some(records)));
        host.start_pass_committed();
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        let user = UserId::new("e1kadmin");
        runtime
            .block_on(synced(&embedded, &user, "E1-Kadmin-Pass-1"))
            .unwrap();
        let principal = name("e1kadmin");
        let fail = || {
            let stored = runtime.block_on(handler.read_lock(&user)).unwrap();
            let row = stored.unwrap_or_default().failed(lock_clock());
            let rows = [LockWrite {
                user: user.clone(),
                uuid: None,
                row: Some(row),
                split: None,
            }];
            runtime.block_on(handler.write_locks("0", &rows)).unwrap();
        };
        let count = || runtime.block_on(handler.read_lock(&user)).unwrap().unwrap();
        let mit = kadm5_mask::FAIL_AUTH_COUNT | kadm5_mask::TL_DATA;
        for (label, carried, counted) in [("1970", 0_u32, 3), ("a time to come", u32::MAX, 4)] {
            (0..3).for_each(|_| fail());
            assert_eq!(count().fail_count, counted, "{label}: counted first");
            let mut unlock = modify_of(mit, &[UNLOCKED], None);
            unlock.tl_data[0].contents = carried.to_le_bytes().to_vec();
            let intent = intent_of(Operation::Modify, kadmin(false), &["e1kadmin"], &mask(mit));
            let edit = |s: &mut PrincipalStore| {
                s.modify_principal_in(&principal, "EXAMPLE.COM", unlock.clone(), ADMIN)
            };
            let before = lock_clock();
            let answer = kadmin_write(&store, true, intent, &principal, &edit);
            let after = lock_clock();
            let row = count();
            let at = row.last_admin_unlock.unwrap();
            assert_eq!((answer.as_str(), row.fail_count), ("written", 0), "{label}");
            assert!(
                before <= at && at <= after,
                "{label}: {before} {at} {after}"
            );
            fail();
            assert_eq!(
                count().fail_count,
                1,
                "{label}: the next failure counts from 1"
            );
        }
        let unlocks = details(&pool, &runtime, "account_unlock");
        let by = sources(&pool, &runtime, "account_unlock");
        assert_eq!(unlocks, vec![UNLOCKED_BY_KADMIN.to_owned(); 2]);
        assert_eq!(by, vec![("kadmin".to_owned(), Some(ADMIN.to_owned())); 2]);
        lockout().forget(&user);
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    fn alias_targets(pool: &DatabaseConnection, runtime: &Runtime) -> Vec<(String, String)> {
        let query = "SELECT name, alias_target FROM kerberos_principals \
                     WHERE alias_target IS NOT NULL";
        let statement = sea_orm::Statement::from_string(pool.get_database_backend(), query);
        let mut found: Vec<(String, String)> = runtime
            .block_on(pool.query_all(statement))
            .unwrap()
            .iter()
            .map(|row| {
                let name = row.try_get::<String>("", "name").unwrap();
                (name, row.try_get::<String>("", "alias_target").unwrap())
            })
            .collect();
        found.sort();
        found
    }

    fn alias_column_on(connect: Reconnect) {
        use lldap_test_utils::recording_log::LogGuard;

        let guard = LogGuard::install();
        let runtime = runtime();
        let temp = TempRealm::new();
        let profile = boot::profile(&temp.settings);
        let (committer, pool) = committer_on(connect, &runtime);
        add_user(&pool, &runtime, "bob");
        let host = Arc::new(SqlRealm::new(committer.store()).serving("EXAMPLE.COM", None));
        host.start_pass_committed();
        let store = krb5_kdc::shared_dump(
            boot::open_store(&temp.settings, &profile, host.clone()).unwrap(),
        );
        let own = |edit: &dyn Fn(&mut krb5_kdc::PrincipalStore) -> Result<(), StoreError>| {
            store
                .write()
                .unwrap()
                .change_committing(committing(&*host), |s| edit(s))
                .unwrap()
                .unwrap();
        };
        let alias = |from: &str, onto: &str| {
            let (from, onto) = (name(from), name(onto));
            own(&|s: &mut krb5_kdc::PrincipalStore| {
                s.create_alias_in(&from, "EXAMPLE.COM", &onto, "EXAMPLE.COM", "test")
            });
        };
        let kadmin_alias = |from: &str, onto: &str, declared: bool| {
            let intent = intent_of(
                Operation::CreateAlias,
                kadmin(false),
                &[from, onto],
                &nothing(),
            );
            let (from, onto) = (name(from), name(onto));
            let edit = |s: &mut krb5_kdc::PrincipalStore| {
                s.create_alias_in(&from, "EXAMPLE.COM", &onto, "EXAMPLE.COM", ADMIN)
            };
            kadmin_write(&store, declared, intent, &onto, &edit)
        };
        let rows = || -> Rows {
            let events = guard.recorder().take_events().into_iter();
            events
                .filter(|e| e.kind != LogKind::Bind)
                .map(|e| (e.kind, e.target, e.detail))
                .collect()
        };
        let svc = name("HTTP/web.example.com");
        own(&|s: &mut krb5_kdc::PrincipalStore| {
            s.insert_new_randkey(&svc, "EXAMPLE.COM", &[], "test")
        });
        alias("y", "bob");
        alias("x", "y");
        rows();

        let held = host.load().unwrap();
        let through_x: Vec<_> = [false, true]
            .into_iter()
            .map(|declared| {
                let answer = kadmin_alias("z", "x", declared);
                (declared, answer, host.load().unwrap() == held, rows())
            })
            .collect();
        let protect = |principal: &str, sent: &str| {
            let sent = format!(" (requested as {sent}@EXAMPLE.COM)");
            let logged = denial_as(principal, "create_alias", "PROTECT_PRINCIPAL", &sent);
            ("PROTECT_PRINCIPAL".to_owned(), true, logged)
        };
        let (answer, unchanged, logged) = protect("bob@EXAMPLE.COM", "x");
        assert_eq!(
            through_x,
            vec![
                (false, answer.clone(), unchanged, logged.clone()),
                (true, answer, unchanged, logged)
            ],
            "z onto x, x onto y, y onto bob: refused at the commit, and at prepare"
        );

        for hop in 0..=10 {
            alias(&format!("a{hop}"), &format!("a{}", hop + 1));
        }
        let reach: Vec<String> = host
            .targets(&["a0@EXAMPLE.COM".to_owned()])
            .into_iter()
            .map(|named| named.principal)
            .collect();
        add_user(&pool, &runtime, "a11");
        let past = (kadmin_alias("d", "a0", false), rows());
        add_user(&pool, &runtime, "a10");
        let at = (kadmin_alias("e", "a0", false), rows());
        let (answer, _, logged) = protect("a10@EXAMPLE.COM", "a0");
        assert_eq!(
            (reach, past, at),
            (
                (0..=10).map(|hop| format!("a{hop}@EXAMPLE.COM")).collect(),
                ("written".to_owned(), Vec::new()),
                (answer, logged)
            ),
            "a chain is followed 10 hops, as kerber-rust resolves it, and no further"
        );

        let web = kadmin_alias("web", "HTTP/web.example.com", true);
        let mut written: Vec<(String, String)> = (0..=10)
            .map(|hop| (format!("a{hop}"), format!("a{}", hop + 1)))
            .collect();
        written.extend(
            [
                ("d", "a0"),
                ("web", "HTTP/web.example.com"),
                ("x", "y"),
                ("y", "bob"),
            ]
            .map(|(row, target)| (row.to_owned(), target.to_owned())),
        );
        written.sort();
        let filled = alias_targets(&pool, &runtime);
        let delete = intent_of(Operation::Delete, kadmin(false), &["web"], &nothing());
        let edit = |s: &mut krb5_kdc::PrincipalStore| s.remove_in(&name("web"), "EXAMPLE.COM");
        let deleted = kadmin_write(&store, true, delete, &name("web"), &edit);
        let kept = alias_targets(&pool, &runtime);
        let mut without_web = written.clone();
        without_web.retain(|(row, _)| row != "web");
        assert_eq!(
            (web, filled, deleted, kept, rows()),
            (
                "written".to_owned(),
                written,
                "written".to_owned(),
                without_web.clone(),
                Vec::new()
            ),
            "each alias row carries its target's row name; a delete takes the row with it"
        );

        let held = host.load().unwrap();
        sql(
            &pool,
            &runtime,
            "UPDATE kerberos_principals SET alias_target = NULL",
        );
        let emptied = alias_targets(&pool, &runtime).len();
        let ready = Arc::new(AtomicBool::new(true));
        let embedded = EmbeddedKerberos::new(store.clone(), &temp.settings, ready, host.clone());
        let pass = runtime.block_on(embedded.start_pass(Vec::new())).unwrap();
        let refilled = alias_targets(&pool, &runtime);
        let again = runtime.block_on(embedded.start_pass(Vec::new())).unwrap();
        let after_again = alias_targets(&pool, &runtime);
        let once_more = host.fill_alias_targets(&[("x".to_owned(), "y@EXAMPLE.COM".to_owned())]);
        let refused = kadmin_alias("f", "x", false);
        assert_eq!(
            (
                emptied,
                (pass.marked, pass.removed, pass.disabled),
                refilled,
                host.load().unwrap() == held,
                (again.marked, again.removed, again.disabled),
                after_again,
                once_more.map_err(|e| e.to_string()),
                refused
            ),
            (
                0,
                (0, 0, 0),
                without_web.clone(),
                true,
                (0, 0, 0),
                without_web,
                Ok(0),
                "PROTECT_PRINCIPAL".to_owned()
            ),
            "alias rows written before the column: the start pass fills it, records unchanged"
        );
        drop((embedded, store, host));
        runtime.block_on(committer.shutdown());
    }

    #[test]
    #[serial]
    fn test_the_alias_target_column_on_sqlite() {
        let dir = std::env::temp_dir().join(format!("klldap-aliases-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.join("aliases.db").display());
        alias_column_on(&|runtime| sqlite_one_connection(&url, runtime));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[serial]
    #[ignore = "needs a scratch Postgres via KLLDAP_TEST_DATABASE_URL (gate postgres lane)"]
    fn test_the_alias_target_column_on_postgres() {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            eprintln!("KLLDAP_TEST_DATABASE_URL is not a postgres URL; skipping");
            return;
        }
        let schema = format!("klldap_aliases_{}", std::process::id());
        alias_column_on(&|runtime| {
            runtime.block_on(async {
                let admin = Database::connect(url.as_str()).await.unwrap();
                for sql in [
                    format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
                    format!("CREATE SCHEMA {schema}"),
                ] {
                    admin.execute_unprepared(&sql).await.unwrap();
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
    #[serial]
    #[ignore = "needs a scratch MySQL via KLLDAP_TEST_DATABASE_URL (mysql lane)"]
    fn test_the_alias_target_column_on_mysql() {
        let Ok(url) = std::env::var("KLLDAP_TEST_DATABASE_URL") else {
            eprintln!("KLLDAP_TEST_DATABASE_URL not set; skipping");
            return;
        };
        if !url.starts_with("mysql://") {
            eprintln!("KLLDAP_TEST_DATABASE_URL is not a mysql URL; skipping");
            return;
        }
        let db = format!("klldap_aliases_{}", std::process::id());
        let server = url
            .split('?')
            .next()
            .unwrap_or(&url)
            .rsplit_once('/')
            .unwrap()
            .0
            .to_owned();
        alias_column_on(&|runtime| {
            runtime.block_on(async {
                let admin = Database::connect(format!("{server}/mysql")).await.unwrap();
                for sql in [
                    format!("DROP DATABASE IF EXISTS `{db}`"),
                    format!("CREATE DATABASE `{db}`"),
                ] {
                    admin.execute_unprepared(&sql).await.unwrap();
                }
                let mut opts = ConnectOptions::new(format!("{server}/{db}"));
                opts.max_connections(2).sqlx_logging(false);
                Database::connect(opts).await.unwrap()
            })
        });
    }

    #[test]
    fn test_klldap_never_holds_the_realm_key() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let sources = [
            ("admission.rs", include_str!("admission.rs")),
            (
                "admission/tests/networks_rows.rs",
                include_str!("admission/tests/networks_rows.rs"),
            ),
            ("admission_test.rs", include_str!("admission_test.rs")),
            ("boot.rs", include_str!("boot.rs")),
            ("embedded.rs", include_str!("embedded.rs")),
            ("lib.rs", include_str!("lib.rs")),
            ("migrate.rs", include_str!("migrate.rs")),
            ("policy.rs", include_str!("policy.rs")),
            ("rotate.rs", include_str!("rotate.rs")),
            ("seam.rs", include_str!("seam.rs")),
        ];
        fn listed(dir: &std::path::Path, at: &str, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap().map(Result::unwrap) {
                let name = format!("{at}{}", entry.file_name().to_string_lossy());
                match entry.file_type().unwrap().is_dir() {
                    true => listed(&entry.path(), &format!("{name}/"), out),
                    false => out.push(name),
                }
            }
        }
        let mut on_disk = Vec::new();
        listed(std::path::Path::new(dir), "", &mut on_disk);
        on_disk.sort();
        let scanned: Vec<String> = sources.iter().map(|(file, _)| (*file).to_owned()).collect();
        let banned = [
            concat!("host_seal", "_key"),
            concat!("open_", "principal"),
            concat!("Seal", "Key"),
            concat!("load_dump_with", "_stash("),
            concat!("read_stash", "_file"),
        ];
        let found: Vec<(&str, &str)> = sources
            .iter()
            .flat_map(|(file, text)| {
                banned
                    .iter()
                    .filter(|name| text.contains(**name))
                    .map(move |name| (*file, *name))
            })
            .collect();
        assert_eq!(
            (on_disk, found),
            (scanned, Vec::new()),
            "every source file is scanned, and none takes the realm's key, opens a record or reads the stash"
        );
    }

    #[test]
    fn test_the_verdict_on_each_intent() {
        type Row = (Operation, bool, fn(&mut WriteIntent), &'static str);
        fn password(intent: &mut WriteIntent, text: &str, keepold: u32) {
            intent.password = Some(Zeroizing::new(text.as_bytes().to_vec()));
            intent.keepold = Some(keepold);
        }
        let rows: [Row; 16] = [
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
                |i| i.client_mask = Some(kadm5_mask::FAIL_AUTH_COUNT | kadm5_mask::TL_DATA),
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
            (
                Operation::ChangePassword,
                true,
                |i| password(i, "a\0aaaaaaa", 0),
                "PASS_Q_GENERIC",
            ),
            (
                Operation::ChangePassword,
                true,
                |i| {
                    i.password = Some(Zeroizing::new(NOT_UTF8.to_vec()));
                    i.keepold = Some(0);
                },
                "PASS_Q_GENERIC",
            ),
        ];
        let bob = krb5_kdc::PrincipalBuilder::new(name("bob"), "EXAMPLE.COM").build();
        for (operation, owned, fill, expected) in rows {
            let mut intent = WriteIntent::new(operation, Caller::Embedder);
            fill(&mut intent);
            let change = HostChange {
                intent,
                rows: vec![RowChange {
                    id: "bob@EXAMPLE.COM".to_owned(),
                    before: Some(bob.clone()),
                    after: Some(bob.clone()),
                    mask: 0,
                    host_owned: owned,
                }],
                prepared: None,
                batch: RealmBatch {
                    upsert_principals: vec![row(1, None)],
                    ..RealmBatch::default()
                },
            };
            let got = match verdict(&change, "EXAMPLE.COM") {
                Ok(Verdict::Write { new, onto }) if new.is_empty() && onto.is_empty() => {
                    "written".to_owned()
                }
                Ok(Verdict::Unlock(named)) => format!("unlock {}", named.principal),
                Ok(Verdict::Password(named)) => format!("password {}", named.principal),
                Ok(Verdict::Deny { code, .. }) => code_name(code).to_owned(),
                Err(KerberosStoreError::Refused(_)) => "refused".to_owned(),
                other => format!("{other:?}"),
            };
            assert_eq!(got, expected, "{operation:?}, owned {owned}");
        }
        let mut alias = krb5_kdc::PrincipalBuilder::new(name("carl"), "EXAMPLE.COM").build();
        alias.tl_data.push(krb5_kdc::TlData {
            ty: krb5_kdc::TL_ALIAS_TARGET,
            contents: b"bobby@EXAMPLE.COM\0".to_vec(),
        });
        let change = HostChange {
            intent: WriteIntent::new(Operation::CreateAlias, Caller::Embedder),
            rows: vec![RowChange {
                id: "carl@EXAMPLE.COM".to_owned(),
                before: None,
                after: Some(alias),
                mask: 0,
                host_owned: false,
            }],
            prepared: None,
            batch: RealmBatch::default(),
        };
        assert_eq!(
            verdict(&change, "EXAMPLE.COM").map(shown),
            Ok("ask carl@EXAMPLE.COM as carl, onto bobby@EXAMPLE.COM".to_owned()),
            "an alias row: its target is asked of the directory, and followed in its rows"
        );
    }

    #[test]
    #[serial]
    fn test_kadmin_counts_a_new_password_as_password_length() {
        use lldap_auth::password_length;
        const MEETS: &str = "meets the minimum";
        type Row = (
            &'static str,
            usize,
            (usize, usize),
            &'static str,
            &'static str,
        );
        let rows: [Row; 5] = [
            (
                "ääääääää",
                12,
                (8, 16),
                "password bob@EXAMPLE.COM",
                "the password is shorter than 12 characters",
            ),
            (
                "ääää",
                8,
                (4, 8),
                "PASS_Q_TOOSHORT",
                "the password is shorter than 8 characters",
            ),
            (
                "e\u{301}e\u{301}e\u{301}e\u{301}",
                8,
                (8, 12),
                "password bob@EXAMPLE.COM",
                MEETS,
            ),
            (
                "",
                8,
                (0, 0),
                "PASS_Q_TOOSHORT",
                "the password is shorter than 8 characters",
            ),
            (
                "a\0aaaaaaa",
                8,
                (9, 9),
                "PASS_Q_GENERIC",
                "the password must be valid UTF-8 without a NUL character (U+0000)",
            ),
        ];
        let named = || Named::of("bob@EXAMPLE.COM", "EXAMPLE.COM");
        let judged = |text: &'static str, min: usize| {
            let mut intent = WriteIntent::new(Operation::ChangePassword, Caller::Embedder);
            intent.password = Some(Zeroizing::new(text.as_bytes().to_vec()));
            intent.keepold = Some(0);
            let verdict = match password_verdict(&intent, named()) {
                Verdict::Password(to) => format!("password {}", to.principal),
                Verdict::Deny { code, .. } => code_name(code).to_owned(),
                other => format!("{other:?}"),
            };
            let held = match held_to(&intent, &named(), text.as_bytes(), min) {
                Ok(()) => MEETS.to_owned(),
                Err(KerberosStoreError::Denied(denial)) => denial.text,
                Err(e) => e.to_string(),
            };
            let counted = (password_length(text), text.len());
            (text, min, counted, verdict, held)
        };
        let got = rows.map(|(text, min, ..)| judged(text, min));
        let want = rows.map(|(text, min, counts, verdict, held)| {
            (text, min, counts, verdict.to_owned(), held.to_owned())
        });
        assert_eq!(got, want);
        for (text, min, _, verdict, held) in rows.into_iter().filter(|row| !row.0.contains('\0')) {
            assert_eq!(
                (verdict == "PASS_Q_TOOSHORT", held != MEETS),
                (password_length(text) < 8, password_length(text) < min),
                "{text:?}: the verdict holds the floor and the commit the minimum, as counted"
            );
        }
    }

    #[test]
    fn test_an_unlock_is_judged_by_its_rows() {
        type Case = (
            &'static str,
            u32,
            u32,
            fn(&mut Principal),
            fn(&mut HostChange),
            &'static str,
        );
        fn tl(ty: i32, contents: &[u8]) -> TlData {
            TlData {
                ty,
                contents: contents.to_vec(),
            }
        }
        fn unlocked(p: &mut Principal) {
            p.fail_auth_count = 0;
            p.tl_data.retain(|t| t.ty != TL_MOD_PRINC);
            p.tl_data
                .push(tl(TL_MOD_PRINC, b"\x02\0\0\0admin/admin@EXAMPLE.COM\0"));
        }
        fn mit_unlocked(p: &mut Principal) {
            unlocked(p);
            p.tl_data.push(tl(TL_LAST_ADMIN_UNLOCK, &[2, 0, 0, 0]));
        }
        let (unlock, tl_bit) = (kadm5_mask::FAIL_AUTH_COUNT, kadm5_mask::TL_DATA);
        let stamp = kadm5_mask::MOD_TIME | kadm5_mask::MOD_NAME;
        let (mit, rows) = (unlock | tl_bit, tl_bit | stamp);
        let same: fn(&mut HostChange) = |_| {};
        let pass = "unlock bob@EXAMPLE.COM";
        let deny = "PROTECT_PRINCIPAL bob@EXAMPLE.COM";
        let cases: [Case; 24] = [
            ("MIT's unlock", mit, rows, mit_unlocked, same, pass),
            (
                "an existing TL entry removed",
                mit,
                rows,
                |p| {
                    mit_unlocked(p);
                    p.tl_data.retain(|t| t.ty != krb5_kdc::TL_LAST_PWD_CHANGE);
                },
                same,
                deny,
            ),
            (
                "the last password change moved",
                mit,
                rows,
                |p| {
                    mit_unlocked(p);
                    for t in &mut p.tl_data {
                        if t.ty == krb5_kdc::TL_LAST_PWD_CHANGE {
                            t.contents = vec![9, 0, 0, 0];
                        }
                    }
                },
                same,
                deny,
            ),
            (
                "the KVNO, by the mask",
                mit,
                rows | kadm5_mask::KVNO,
                mit_unlocked,
                same,
                deny,
            ),
            (
                "the last failure time",
                mit,
                rows,
                |p| {
                    mit_unlocked(p);
                    p.last_failed = 7;
                },
                same,
                deny,
            ),
            ("the one-bit unlock", unlock, stamp, unlocked, same, pass),
            (
                "a second TL entry",
                mit,
                rows,
                |p| {
                    mit_unlocked(p);
                    p.tl_data.push(tl(0x0701, &[1, 2, 3, 4]));
                },
                same,
                deny,
            ),
            (
                "one TL entry of another type",
                mit,
                rows,
                |p| {
                    unlocked(p);
                    p.tl_data.push(tl(0x0701, &[1, 2, 3, 4]));
                },
                same,
                deny,
            ),
            (
                "an unlock entry of 8 bytes",
                mit,
                rows,
                |p| {
                    unlocked(p);
                    p.tl_data.push(tl(TL_LAST_ADMIN_UNLOCK, &[0; 8]));
                },
                same,
                deny,
            ),
            (
                "two unlock entries",
                mit,
                rows,
                |p| {
                    mit_unlocked(p);
                    p.tl_data.push(tl(TL_LAST_ADMIN_UNLOCK, &[3, 0, 0, 0]));
                },
                same,
                deny,
            ),
            (
                "two stamps",
                mit,
                rows,
                |p| {
                    mit_unlocked(p);
                    p.tl_data.push(tl(TL_MOD_PRINC, b"x\0"));
                },
                same,
                deny,
            ),
            (
                "an attribute the mask does not show",
                mit,
                rows,
                |p| {
                    mit_unlocked(p);
                    p.attributes ^= krb5_kdc::KDB_DISALLOW_POSTDATED;
                },
                same,
                deny,
            ),
            (
                "a string attribute",
                mit,
                rows,
                |p| {
                    mit_unlocked(p);
                    p.string_attrs.push(("note".to_owned(), "x".to_owned()));
                },
                same,
                deny,
            ),
            (
                "keys, by the mask",
                mit,
                rows | kadm5_mask::KEY_DATA,
                mit_unlocked,
                same,
                deny,
            ),
            (
                "the fail count kept",
                mit,
                rows,
                |p| {
                    mit_unlocked(p);
                    p.fail_auth_count = 5;
                },
                same,
                deny,
            ),
            (
                "the client asked for an attribute",
                mit | kadm5_mask::ATTRIBUTES,
                rows,
                mit_unlocked,
                same,
                deny,
            ),
            (
                "a second record",
                mit,
                rows,
                mit_unlocked,
                |c| {
                    let other = RowChange {
                        id: "carol@EXAMPLE.COM".to_owned(),
                        host_owned: false,
                        ..c.rows[0].clone()
                    };
                    c.rows.push(other);
                },
                deny,
            ),
            (
                "the realm's state",
                mit,
                rows,
                mit_unlocked,
                |c| {
                    c.batch.realm = Some(RealmState {
                        realm: "EXAMPLE.COM".to_owned(),
                        state: vec![1],
                    });
                },
                deny,
            ),
            (
                "no record before",
                mit,
                rows,
                mit_unlocked,
                |c| c.rows[0].before = None,
                deny,
            ),
            (
                "the batch upserts the judged row",
                mit,
                rows,
                mit_unlocked,
                same,
                pass,
            ),
            (
                "the batch upserts nothing",
                mit,
                rows,
                mit_unlocked,
                |c| c.batch.upsert_principals.clear(),
                deny,
            ),
            (
                "the batch upserts the judged row twice",
                mit,
                rows,
                mit_unlocked,
                |c| c.batch.upsert_principals.push(row(1, None)),
                deny,
            ),
            (
                "the batch upserts another row too",
                mit,
                rows,
                mit_unlocked,
                |c| {
                    c.batch.upsert_principals.push(PrincipalRow {
                        name: "alice@EXAMPLE.COM".to_owned(),
                        ..row(1, None)
                    })
                },
                deny,
            ),
            (
                "the batch deletes a principal",
                mit,
                rows,
                mit_unlocked,
                |c| {
                    c.batch
                        .delete_principals
                        .push("alice@EXAMPLE.COM".to_owned())
                },
                deny,
            ),
        ];
        let mut before = krb5_kdc::PrincipalBuilder::new(name("bob"), "EXAMPLE.COM").build();
        before.fail_auth_count = 5;
        before
            .tl_data
            .push(tl(krb5_kdc::TL_LAST_PWD_CHANGE, &[1, 0, 0, 0]));
        before
            .tl_data
            .push(tl(TL_MOD_PRINC, b"\x01\0\0\0db_creation@EXAMPLE.COM\0"));
        let (mut got, mut want) = (Vec::new(), Vec::new());
        for (label, client_mask, mask, edit, around, expected) in cases {
            let mut after = before.clone();
            edit(&mut after);
            let mut intent = WriteIntent::new(Operation::Modify, Caller::Embedder);
            intent.client_mask = Some(client_mask);
            let mut change = HostChange {
                intent,
                rows: vec![RowChange {
                    id: "bob@EXAMPLE.COM".to_owned(),
                    before: Some(before.clone()),
                    after: Some(after),
                    mask,
                    host_owned: true,
                }],
                prepared: None,
                batch: RealmBatch {
                    upsert_principals: vec![row(1, None)],
                    ..RealmBatch::default()
                },
            };
            around(&mut change);
            let answer = verdict(&change, "EXAMPLE.COM").map(shown);
            got.push((label, answer));
            want.push((label, Ok::<_, KerberosStoreError>(expected.to_owned())));
        }
        assert_eq!(got, want);
    }

    fn shown(verdict: Verdict) -> String {
        match verdict {
            Verdict::Write { new, onto } if new.is_empty() && onto.is_empty() => "pass".to_owned(),
            Verdict::Write { new, onto } => {
                let names: Vec<_> = new
                    .iter()
                    .map(|n| {
                        format!(
                            "{} as {}",
                            n.principal,
                            n.user.as_ref().map_or("", UserId::as_str)
                        )
                    })
                    .chain(onto.iter().map(|target| format!("onto {target}")))
                    .collect();
                format!("ask {}", names.join(", "))
            }
            Verdict::Unlock(named) => format!("unlock {}{}", named.principal, named.requested_as()),
            Verdict::Password(named) => {
                format!("password {}{}", named.principal, named.requested_as())
            }
            Verdict::Deny { code, named } => format!(
                "{} {}{}",
                code_name(code),
                named.principal,
                named.requested_as()
            ),
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
        let rows: [Row; 32] = [
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
                "rename of an alias of an owned record",
                Operation::Rename,
                bob,
                ["bobby@EXAMPLE.COM", "bobbie@EXAMPLE.COM"],
                |_| {},
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM (requested as bobby@EXAMPLE.COM)",
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
                "alias onto an owned record through an alias",
                Operation::CreateAlias,
                bob,
                ["carl@EXAMPLE.COM", "bobby@EXAMPLE.COM"],
                |_| {},
                "PROTECT_PRINCIPAL bob@EXAMPLE.COM (requested as bobby@EXAMPLE.COM)",
            ),
            (
                "alias onto a user's name, no record",
                Operation::CreateAlias,
                None,
                ["carl@EXAMPLE.COM", "alice@EXAMPLE.COM"],
                |_| {},
                "ask carl@EXAMPLE.COM as carl, onto alice@EXAMPLE.COM",
            ),
            (
                "alias named as a user",
                Operation::CreateAlias,
                svc,
                ["alice@EXAMPLE.COM", "svc@EXAMPLE.COM"],
                |_| {},
                "ask alice@EXAMPLE.COM as alice, onto svc@EXAMPLE.COM",
            ),
            (
                "alias named as a case twin, no target",
                Operation::CreateAlias,
                None,
                ["Alice@EXAMPLE.COM", "svc@EXAMPLE.COM"],
                |_| {},
                "ask Alice@EXAMPLE.COM as alice, onto svc@EXAMPLE.COM",
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
                "cpw through an alias",
                Operation::ChangePassword,
                bob,
                ["bobby@EXAMPLE.COM", ""],
                |i| password(i, "Bob-Password-2", 0),
                "password bob@EXAMPLE.COM (requested as bobby@EXAMPLE.COM)",
            ),
            (
                "cpw not UTF-8",
                Operation::ChangePassword,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |i| {
                    i.password = Some(Zeroizing::new(NOT_UTF8.to_vec()));
                    i.keepold = Some(0);
                },
                "PASS_Q_GENERIC bob@EXAMPLE.COM",
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
                "cpw with a NUL, 9 characters",
                Operation::ChangePassword,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |i| password(i, "a\0aaaaaaa", 0),
                "PASS_Q_GENERIC bob@EXAMPLE.COM",
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
                "MIT's unlock: the count and one TL entry",
                Operation::Modify,
                bob,
                ["bob@EXAMPLE.COM", ""],
                |i| i.client_mask = Some(kadm5_mask::FAIL_AUTH_COUNT | kadm5_mask::TL_DATA),
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
                "delete through an alias",
                Operation::Delete,
                bob,
                ["bobby@EXAMPLE.COM", ""],
                |_| {},
                "pass",
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
        for seconds in [0, 2_147_483_648, u32::MAX] {
            assert_eq!(time(seconds), when(i64::from(seconds)), "{seconds}");
        }
        let refused = principal_row(row(u32::MAX, None)).unwrap_err();
        assert!(
            matches!(&refused, KerberosStoreError::Refused(why) if why.contains("key version")),
            "{refused:?}"
        );
    }
}
