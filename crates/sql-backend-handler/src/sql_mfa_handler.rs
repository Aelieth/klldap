use crate::SqlBackendHandler;
use crate::sql_lockout_handler::numbered;
use crate::sql_totp_steps::{Mark, clear_used, mark_in, mark_used, refund, reserve};
use crate::sql_used_proofs::take_proof_id;
use async_trait::async_trait;
use lldap_domain::types::{MFA_TYPE_TOTP, TotpEnrollmentStart, UserId};
use lldap_domain_handlers::handler::MfaBackendHandler;
use lldap_domain_handlers::logging::{self, LogKind};
use lldap_domain_handlers::mfa::{
    MFA_DISABLED_GROUP, MfaEnrollmentStatus, MfaPolicy, MfaRequirement, MfaResetReason,
    mfa_requirement,
};
use lldap_domain_model::{
    error::{DomainError, Result},
    model::{self, UserColumn},
};
use lldap_mfa::{
    MfaError, PASSWORD_PROOF_REQUIRED, TOTP_CODE_ALREADY_USED, TOTP_CURRENT_CODE_REQUIRED,
    TOTP_ENROLLMENT_EXPIRED, TOTP_STEP_SECS, TOTP_TOO_MANY_ATTEMPTS, open_enrollment_proof,
    seal_enrollment_proof,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait,
    IsolationLevel, QueryFilter, Statement, TransactionTrait, Value, sea_query::Expr,
};
#[cfg(any(test, feature = "test-clock"))]
use std::cell::Cell;
use tracing::{info, instrument, warn};

const TOTP_ISSUER: &str = "KLLDAP";

#[cfg(any(test, feature = "test-clock"))]
thread_local! {
    static TEST_NOW: Cell<Option<i64>> = const { Cell::new(None) };
}

#[cfg(any(test, feature = "test-clock"))]
pub fn set_enrollment_clock(now: Option<i64>) {
    TEST_NOW.with(|clock| clock.set(now));
}

/// The injected clock for one test row; reset when the row ends, by a panic too.
#[cfg(test)]
pub(crate) struct PinnedClock;

#[cfg(test)]
impl Drop for PinnedClock {
    fn drop(&mut self) {
        set_enrollment_clock(None);
    }
}

#[cfg(test)]
pub(crate) fn pin_clock(at: i64) -> PinnedClock {
    set_enrollment_clock(Some(at));
    PinnedClock
}

pub(crate) fn now_unix() -> i64 {
    #[cfg(any(test, feature = "test-clock"))]
    if let Some(now) = TEST_NOW.with(|clock| clock.get()) {
        return now;
    }
    chrono::Utc::now().timestamp()
}

fn refuse_proof(user_id: &UserId) -> DomainError {
    logging::record_failure(
        LogKind::MfaEnroll,
        Some(user_id.as_str()),
        "password proof required",
    );
    DomainError::AuthenticationError(PASSWORD_PROOF_REQUIRED.to_string())
}

impl SqlBackendHandler {
    /// A first enrollment's proof: it opens, names this user, and was never used on any server.
    async fn take_proof(&self, user_id: &UserId, token: Option<&str>, now: i64) -> Result<()> {
        let Some(token) = token.filter(|token| !token.is_empty()) else {
            return Err(refuse_proof(user_id));
        };
        let Ok(proof) = open_enrollment_proof(&self.sealing_key(), token, now) else {
            return Err(refuse_proof(user_id));
        };
        if proof.user_id != user_id.as_str() {
            return Err(refuse_proof(user_id));
        }
        match take_proof_id(&self.sql_pool, &proof.id, proof.expiry_unix).await {
            Ok(true) => {
                self.note_codes_written();
                Ok(())
            }
            Ok(false) => Err(refuse_proof(user_id)),
            Err(e) => {
                warn!("The used enrollment proofs could not be read or written for {user_id}: {e}");
                let target = Some(user_id.as_str());
                logging::record_failure(LogKind::MfaEnroll, target, "proof: unreadable");
                Err(DomainError::AuthenticationError(format!(
                    "Password proof unreadable for {user_id}"
                )))
            }
        }
    }
}

/// Why a code was refused: one log detail and one error message each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TotpRejection {
    NotEnrolled,
    ReenrollmentRequired,
    TooManyAttempts,
    Invalid,
    Replayed,
    Unreadable,
}

pub(crate) type TotpVerdict = std::result::Result<(), TotpRejection>;

impl TotpRejection {
    pub(crate) fn detail(self) -> &'static str {
        match self {
            Self::NotEnrolled => "not enrolled",
            Self::ReenrollmentRequired => "totp re-enrollment required",
            Self::TooManyAttempts => "totp attempts exceeded",
            Self::Invalid => "invalid totp",
            Self::Replayed => "totp replayed",
            Self::Unreadable => "totp: unreadable",
        }
    }

    pub(crate) fn into_error(self, user_id: &UserId) -> DomainError {
        DomainError::AuthenticationError(match self {
            Self::NotEnrolled => format!("User {user_id} is not enrolled in TOTP MFA"),
            Self::ReenrollmentRequired => format!("TOTP re-enrollment required for {user_id}"),
            Self::TooManyAttempts => format!("{TOTP_TOO_MANY_ATTEMPTS} for {user_id}"),
            Self::Invalid => format!("Invalid TOTP code for {user_id}"),
            Self::Replayed => format!("{TOTP_CODE_ALREADY_USED} for {user_id}"),
            Self::Unreadable => format!("TOTP state unreadable for {user_id}"),
        })
    }

    /// The database could not answer: refused, never judged from memory.
    fn unreadable(user_id: &UserId, e: DomainError) -> Self {
        warn!("The TOTP state of {user_id} could not be read or written: {e}");
        Self::Unreadable
    }
}

/// The user's stored sealed factor, with the user's row locked where the dialect locks rows.
async fn stored_factor(txn: &impl ConnectionTrait, user_id: &UserId) -> Result<Option<String>> {
    let backend = txn.get_database_backend();
    let lock = if backend == DbBackend::Sqlite {
        ""
    } else {
        " FOR UPDATE"
    };
    let sql = format!("SELECT totp_secret FROM users WHERE user_id = ?{lock}");
    let user = Value::from(user_id.as_str().to_owned());
    let read = Statement::from_sql_and_values(backend, numbered(backend, &sql), [user]);
    Ok(match txn.query_one(read).await? {
        Some(row) => row.try_get_by_index::<Option<String>>(0)?,
        None => None,
    })
}

/// The user's factor and the old key's used marks change together, in the caller's transaction.
async fn change_factor(
    txn: &impl ConnectionTrait,
    user_id: &UserId,
    totp_secret: Option<String>,
    mfa_type: Option<String>,
) -> Result<()> {
    let user_update = model::users::ActiveModel {
        user_id: ActiveValue::Set(user_id.clone()),
        totp_secret: ActiveValue::Set(totp_secret),
        mfa_type: ActiveValue::Set(mfa_type),
        modified_date: ActiveValue::Set(chrono::Utc::now().naive_utc()),
        ..Default::default()
    };
    user_update.update(txn).await?;
    clear_used(txn, Some(user_id)).await
}

impl SqlBackendHandler {
    async fn get_user_model(&self, user_id: &UserId) -> Result<model::users::Model> {
        model::User::find_by_id(user_id.clone())
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))
    }

    // Both columns are always written together: no orphan sealed secrets.
    pub(crate) async fn write_mfa_columns(
        &self,
        user_id: &UserId,
        totp_secret: Option<String>,
        mfa_type: Option<String>,
    ) -> Result<()> {
        let txn = self.sql_pool.begin().await?;
        change_factor(&txn, user_id, totp_secret, mfa_type).await?;
        txn.commit().await?;
        Ok(())
    }

    // The TOTP secret, the enrollment state and the proof each derive their own key from it.
    pub(crate) fn sealing_key(&self) -> Vec<u8> {
        self.opaque_setup.keypair().private().serialize().to_vec()
    }

    pub(crate) async fn mfa_enrollment_status(
        &self,
        user_id: &UserId,
    ) -> Result<Option<MfaEnrollmentStatus>> {
        let Some(user) = model::User::find_by_id(user_id.clone())
            .one(&self.sql_pool)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(MfaEnrollmentStatus {
            enrolled: user.mfa_type.as_deref() == Some(MFA_TYPE_TOTP),
            exempt: self.is_member_of(user_id, MFA_DISABLED_GROUP).await?,
        }))
    }

    // Reserve before verifying, so a spent allowance cannot keep testing codes; a right code is
    // refunded, used or not, unless its key changed meanwhile: that one counts as invalid.
    pub(crate) async fn verify_user_totp(
        &self,
        user_id: &UserId,
        code: &str,
    ) -> Result<TotpVerdict> {
        let Some(user) = model::User::find_by_id(user_id.clone())
            .one(&self.sql_pool)
            .await?
        else {
            return Ok(Err(TotpRejection::NotEnrolled));
        };
        let enrolled = user.mfa_type.as_deref() == Some(MFA_TYPE_TOTP);
        let Some(sealed) = user.totp_secret.filter(|_| enrolled) else {
            return Ok(Err(TotpRejection::NotEnrolled));
        };
        let uuid = user.uuid.as_str();
        // A decrypt failure means the server key changed: ask for re-enrollment.
        let Ok(seed) = lldap_mfa::open_totp_secret(&self.sealing_key(), uuid, &sealed) else {
            return Ok(Err(TotpRejection::ReenrollmentRequired));
        };
        let now = now_unix() as u64;
        let step = now / TOTP_STEP_SECS;
        let db = &self.sql_pool;
        match reserve(db, user_id, step).await {
            Ok(true) => self.note_codes_written(),
            Ok(false) => return Ok(Err(TotpRejection::TooManyAttempts)),
            Err(e) => return Ok(Err(TotpRejection::unreadable(user_id, e))),
        }
        let matched = lldap_mfa::totp_matched_step(&seed, code, now)
            .map_err(|e| DomainError::InternalError(format!("TOTP verification failed: {e}")))?;
        let Some(matched) = matched else {
            return Ok(Err(TotpRejection::Invalid));
        };
        let verdict = match mark_used(db, user_id, matched, &sealed).await {
            Ok(Mark::Taken) => Ok(()),
            Ok(Mark::Used) => Err(TotpRejection::Replayed),
            Ok(Mark::KeyChanged) => return Ok(Err(TotpRejection::Invalid)),
            Err(e) => return Ok(Err(TotpRejection::unreadable(user_id, e))),
        };
        if let Err(e) = refund(db, user_id, step).await {
            return Ok(Err(TotpRejection::unreadable(user_id, e)));
        }
        Ok(verdict)
    }

    /// Every sealed secret dies with the server key; one system row records the sweep.
    pub async fn clear_all_mfa(&self) -> Result<u64> {
        let txn = self.sql_pool.begin().await?;
        let cleared = model::User::update_many()
            .col_expr(UserColumn::TotpSecret, Expr::value(None::<String>))
            .col_expr(UserColumn::MfaType, Expr::value(None::<String>))
            .col_expr(
                UserColumn::ModifiedDate,
                Expr::value(chrono::Utc::now().naive_utc()),
            )
            .filter(UserColumn::MfaType.is_not_null())
            .exec(&txn)
            .await?
            .rows_affected;
        clear_used(&txn, None).await?;
        txn.commit().await?;
        if cleared > 0 {
            logging::record(LogKind::MfaReset, None, Some("private key changed"));
            self.policy_cache.poke_fill();
        }
        Ok(cleared)
    }
}

#[async_trait]
impl MfaBackendHandler for SqlBackendHandler {
    async fn mfa_requirement(&self, user_id: &UserId) -> Result<MfaRequirement> {
        if self.mfa_policy == MfaPolicy::Disabled {
            return Ok(MfaRequirement::None);
        }
        let status = self.mfa_enrollment_status(user_id).await?;
        Ok(mfa_requirement(self.mfa_policy, status.as_ref()))
    }

    async fn seal_enrollment_proof(&self, user_id: &UserId) -> Result<Option<String>> {
        let status = self.mfa_enrollment_status(user_id).await?;
        if status.as_ref().is_some_and(|status| status.enrolled) {
            return Ok(None);
        }
        Ok(Some(
            seal_enrollment_proof(&self.sealing_key(), user_id.as_str(), now_unix()).map_err(
                |e| DomainError::InternalError(format!("Could not seal enrollment proof: {e}")),
            )?,
        ))
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn reset_user_mfa(&self, user_id: &UserId, reason: MfaResetReason) -> Result<()> {
        if self.get_user_model(user_id).await?.mfa_type.is_none() {
            return Ok(());
        }
        self.write_mfa_columns(user_id, None, None).await?;
        self.user_written(user_id).await;
        info!(r#"Cleared MFA state for "{}""#, user_id);
        logging::record(LogKind::MfaReset, Some(user_id.as_str()), reason.detail());
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn reset_own_mfa(&self, user_id: &UserId, code: &str) -> Result<()> {
        let target = Some(user_id.as_str());
        if let Err(rejection) = self.verify_user_totp(user_id, code).await? {
            logging::record_failure(LogKind::MfaReset, target, rejection.detail());
            return Err(rejection.into_error(user_id));
        }
        self.write_mfa_columns(user_id, None, None).await?;
        self.user_written(user_id).await;
        info!(r#"Cleared own MFA state for "{}""#, user_id);
        logging::record(LogKind::MfaReset, target, Some("self"));
        Ok(())
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn start_totp_enrollment(
        &self,
        user_id: &UserId,
        current_code: Option<String>,
        enrollment_proof: Option<String>,
    ) -> Result<TotpEnrollmentStart> {
        let target = Some(user_id.as_str());
        let stored = self.get_user_model(user_id).await?;
        let replaces_existing = stored.mfa_type.is_some();
        let stored = stored.totp_secret.filter(|_| replaces_existing);
        if !replaces_existing {
            let token = enrollment_proof.as_deref();
            self.take_proof(user_id, token, now_unix()).await?;
        }
        // Replacing a factor needs the old one, so a stolen session cannot rebind it.
        if replaces_existing {
            let current = current_code.ok_or_else(|| {
                DomainError::AuthenticationError(format!(
                    "{TOTP_CURRENT_CODE_REQUIRED} for {user_id}"
                ))
            })?;
            if let Err(rejection) = self.verify_user_totp(user_id, &current).await? {
                logging::record_failure(LogKind::MfaEnroll, target, rejection.detail());
                return Err(rejection.into_error(user_id));
            }
        }
        let seed = lldap_mfa::generate_seed();
        let secret_base32 = lldap_mfa::seed_base32(&seed);
        let otpauth_uri = lldap_mfa::otpauth_uri(TOTP_ISSUER, user_id.as_str(), &secret_base32);
        // Nothing is persisted until the user proves possession of the seed.
        let state = lldap_mfa::seal_enrollment(
            &self.sealing_key(),
            user_id.as_str(),
            &seed,
            stored.as_deref(),
            now_unix(),
        )
        .map_err(|e| DomainError::InternalError(format!("Could not seal enrollment state: {e}")))?;
        logging::record(LogKind::MfaEnroll, target, Some("started"));
        Ok(TotpEnrollmentStart {
            otpauth_uri,
            secret_base32,
            state,
        })
    }

    #[instrument(skip_all, level = "debug", err(level = "debug"))]
    async fn finish_totp_enrollment(
        &self,
        user_id: &UserId,
        state: &str,
        code: &str,
    ) -> Result<()> {
        let target = Some(user_id.as_str());
        let refuse = |detail: &str, error: DomainError| {
            logging::record_failure(LogKind::MfaEnroll, target, detail);
            error
        };
        let now = now_unix();
        let state = match lldap_mfa::open_enrollment(&self.sealing_key(), state, now) {
            Ok(state) => state,
            Err(MfaError::EnrollmentExpired) => {
                return Err(refuse(
                    "expired enrollment",
                    DomainError::AuthenticationError(format!(
                        "{TOTP_ENROLLMENT_EXPIRED} for {user_id}"
                    )),
                ));
            }
            Err(_) => {
                return Err(refuse(
                    "corrupt enrollment state",
                    DomainError::AuthenticationError(format!(
                        "Corrupted enrollment state for {user_id}"
                    )),
                ));
            }
        };
        // UserId comparison is case-insensitive, unlike the sealed string.
        if UserId::new(&state.user_id) != *user_id {
            return Err(refuse(
                "foreign enrollment state",
                DomainError::AuthenticationError(format!(
                    "Enrollment state does not belong to {user_id}"
                )),
            ));
        }
        let matched = lldap_mfa::totp_matched_step(&state.seed, code, now as u64)
            .map_err(|e| DomainError::InternalError(format!("TOTP verification failed: {e}")))?;
        let Some(matched) = matched else {
            return Err(refuse(
                "invalid code",
                DomainError::AuthenticationError(format!("Invalid TOTP code for {user_id}")),
            ));
        };
        let user = self.get_user_model(user_id).await?;
        let sealed =
            lldap_mfa::seal_totp_secret(&self.sealing_key(), user.uuid.as_str(), &state.seed)
                .map_err(|e| {
                    DomainError::InternalError(format!("Could not seal TOTP secret: {e}"))
                })?;
        let committed = (self.sql_pool.get_database_backend() == DbBackend::MySql)
            .then_some(IsolationLevel::ReadCommitted);
        let txn = self.sql_pool.begin_with_config(committed, None).await?;
        // A state holds only against the factor it was minted from, read under the row's lock.
        let now_stored = stored_factor(&txn, user_id).await?;
        let minted = lldap_mfa::factor_digest(now_stored.as_deref())
            .map_err(|e| DomainError::InternalError(format!("Could not digest the factor: {e}")))?;
        if minted != state.factor {
            txn.rollback().await?;
            return Err(refuse(
                "stale enrollment",
                DomainError::AuthenticationError(format!(
                    "Two-factor changed during enrollment for {user_id}"
                )),
            ));
        }
        let totp = Some(MFA_TYPE_TOTP.to_owned());
        change_factor(&txn, user_id, Some(sealed.clone()), totp).await?;
        let taken = match mark_in(&txn, user_id, matched, &sealed).await {
            Ok(Mark::Taken) => Ok(()),
            Ok(Mark::Used) => Err(TotpRejection::Replayed),
            Ok(Mark::KeyChanged) => Err(TotpRejection::Invalid),
            Err(e) => Err(TotpRejection::unreadable(user_id, e)),
        };
        self.note_codes_written();
        if let Err(rejection) = taken {
            txn.rollback().await?;
            return Err(refuse(rejection.detail(), rejection.into_error(user_id)));
        }
        txn.commit().await?;
        self.user_written(user_id).await;
        info!(r#"TOTP enrollment completed for "{}""#, user_id);
        let detail = if state.replaces_existing {
            "replaced"
        } else {
            "totp"
        };
        logging::record(LogKind::MfaEnroll, target, Some(detail));
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::{get_initialized_db, insert_user_no_password};
    use crate::sql_tables::{DbConnection, init_table};
    use lldap_auth::opaque::server::{ServerSetup, generate_random_private_key};
    use lldap_domain_handlers::logging::{RequestMeta, with_request};
    use lldap_mfa::{
        EnrollmentState, SEALED_BLOB_LEN, SEALED_PREFIX, TOTP_CURRENT_CODE_REQUIRED,
        TOTP_ENROLLMENT_TTL_SECS, TOTP_MAX_ATTEMPTS_PER_STEP, TOTP_SEED_LEN, format_code,
        open_totp_secret, seed_base32, totp_code,
    };
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use serial_test::serial;

    const AT: i64 = 1_770_000_015;

    async fn setup_handler() -> (ServerSetup, SqlBackendHandler) {
        let setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(setup.clone(), get_initialized_db().await);
        (setup, handler)
    }

    fn ikm(setup: &ServerSetup) -> Vec<u8> {
        setup.keypair().private().serialize().to_vec()
    }

    async fn get_mfa_columns(
        handler: &SqlBackendHandler,
        user_id: &str,
    ) -> (Option<String>, Option<String>) {
        let user = model::User::find_by_id(UserId::new(user_id))
            .one(&handler.sql_pool)
            .await
            .unwrap()
            .unwrap();
        (user.totp_secret, user.mfa_type)
    }

    fn open_state(setup: &ServerSetup, state: &str) -> EnrollmentState {
        lldap_mfa::open_enrollment(&ikm(setup), state, now_unix()).unwrap()
    }

    fn current_code(seed: &[u8]) -> (u64, String) {
        let now = now_unix() as u64;
        (now, format_code(totp_code(seed, now).unwrap()))
    }

    fn wrong_code(seed: &[u8]) -> String {
        let now = now_unix() as u64;
        let valid: Vec<u32> = [now - 30, now, now + 30]
            .iter()
            .map(|t| totp_code(seed, *t).unwrap())
            .collect();
        format_code((0..).find(|c| !valid.contains(c)).unwrap())
    }

    async fn fresh_proof(handler: &SqlBackendHandler, user_id: &UserId) -> String {
        handler
            .seal_enrollment_proof(user_id)
            .await
            .unwrap()
            .unwrap()
    }

    // Returns the code spent by enrolling and an unused one from the neighbouring step.
    async fn enroll_user(
        handler: &SqlBackendHandler,
        setup: &ServerSetup,
        user: &str,
    ) -> (UserId, [u8; TOTP_SEED_LEN], String, String) {
        insert_user_no_password(handler, user).await;
        let user_id = UserId::new(user);
        let proof = fresh_proof(handler, &user_id).await;
        let start = handler
            .start_totp_enrollment(&user_id, None, Some(proof))
            .await
            .unwrap();
        let state = open_state(setup, &start.state);
        let (now, code) = current_code(&state.seed);
        handler
            .finish_totp_enrollment(&user_id, &start.state, &code)
            .await
            .unwrap();
        let next = [now + 30, now - 30]
            .iter()
            .map(|t| format_code(totp_code(&state.seed, *t).unwrap()))
            .find(|c| *c != code)
            .unwrap();
        (user_id, state.seed, code, next)
    }

    #[tokio::test]
    async fn test_totp_enrollment_flow() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        insert_user_no_password(&handler, "bob").await;
        let user_id = UserId::new("bob");

        let proof = fresh_proof(&handler, &user_id).await;
        let start = handler
            .start_totp_enrollment(&user_id, None, Some(proof))
            .await
            .unwrap();
        assert!(start.otpauth_uri.starts_with("otpauth://totp/KLLDAP:bob?"));
        assert!(start.otpauth_uri.contains(&start.secret_base32));
        assert!(!format!("{start:?}").contains(&start.secret_base32));
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));

        let state = open_state(&setup, &start.state);
        assert_eq!(seed_base32(&state.seed), start.secret_base32);
        assert!(!state.replaces_existing);
        let (_, code) = current_code(&state.seed);
        handler
            .finish_totp_enrollment(&user_id, &start.state, &code)
            .await
            .unwrap();

        let (totp_secret, mfa_type) = get_mfa_columns(&handler, "bob").await;
        assert_eq!(mfa_type.as_deref(), Some(MFA_TYPE_TOTP));
        let sealed = totp_secret.unwrap();
        let uuid = handler.get_user_model(&user_id).await.unwrap().uuid;
        assert_eq!(
            open_totp_secret(&ikm(&setup), uuid.as_str(), &sealed).unwrap(),
            state.seed
        );
    }

    #[tokio::test]
    async fn test_finish_totp_enrollment_rejected() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        insert_user_no_password(&handler, "bob").await;
        insert_user_no_password(&handler, "john").await;
        let user_id = UserId::new("bob");

        let proof = fresh_proof(&handler, &user_id).await;
        let start = handler
            .start_totp_enrollment(&user_id, None, Some(proof))
            .await
            .unwrap();
        let state = open_state(&setup, &start.state);
        let (now, code) = current_code(&state.seed);

        let err = handler
            .finish_totp_enrollment(&user_id, &start.state, &wrong_code(&state.seed))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));

        let stale = now as i64 - TOTP_ENROLLMENT_TTL_SECS as i64 - 1;
        let expired =
            lldap_mfa::seal_enrollment(&ikm(&setup), "bob", &state.seed, None, stale).unwrap();
        let err = handler
            .finish_totp_enrollment(&user_id, &expired, &code)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(TOTP_ENROLLMENT_EXPIRED));

        let err = handler
            .finish_totp_enrollment(&UserId::new("john"), &start.state, &code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));

        let err = handler
            .finish_totp_enrollment(&user_id, "not-a-sealed-state", &code)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));

        // A state issued for a replacement cannot enroll a user who has no factor.
        let replacing = lldap_mfa::seal_enrollment(
            &ikm(&setup),
            "bob",
            &state.seed,
            Some("v1.another"),
            now as i64,
        )
        .unwrap();
        let err = handler
            .finish_totp_enrollment(&user_id, &replacing, &code)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("changed during enrollment"));
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));
        assert_eq!(get_mfa_columns(&handler, "john").await, (None, None));
    }

    #[tokio::test]
    async fn test_first_enrollment_requires_a_proof() {
        let (_setup, handler) = setup_handler().await;
        insert_user_no_password(&handler, "bob").await;
        insert_user_no_password(&handler, "eve").await;
        let bob = UserId::new("bob");
        let eve = UserId::new("eve");
        let same = |err: &DomainError| err.to_string().contains(PASSWORD_PROOF_REQUIRED);

        let err = handler
            .start_totp_enrollment(&bob, None, None)
            .await
            .unwrap_err();
        assert!(same(&err), "{err}");
        let err = handler
            .start_totp_enrollment(&bob, None, Some("not-a-proof".to_owned()))
            .await
            .unwrap_err();
        assert!(same(&err), "{err}");

        let foreign = fresh_proof(&handler, &eve).await;
        let err = handler
            .start_totp_enrollment(&bob, None, Some(foreign))
            .await
            .unwrap_err();
        assert!(same(&err), "{err}");

        set_enrollment_clock(Some(1_700_000_000));
        let expired = fresh_proof(&handler, &bob).await;
        set_enrollment_clock(Some(1_700_000_000 + 301));
        let err = handler
            .start_totp_enrollment(&bob, None, Some(expired))
            .await
            .unwrap_err();
        set_enrollment_clock(None);
        assert!(same(&err), "{err}");

        set_enrollment_clock(Some(1_700_000_100));
        let still_good = fresh_proof(&handler, &bob).await;
        set_enrollment_clock(Some(1_700_000_100 + 299));
        handler
            .start_totp_enrollment(&bob, None, Some(still_good))
            .await
            .unwrap();
        set_enrollment_clock(None);

        let proof = fresh_proof(&handler, &bob).await;
        handler
            .start_totp_enrollment(&bob, None, Some(proof.clone()))
            .await
            .unwrap();
        let err = handler
            .start_totp_enrollment(&bob, None, Some(proof))
            .await
            .unwrap_err();
        assert!(same(&err), "{err}");
    }

    #[tokio::test]
    async fn test_a_proof_is_used_once_on_every_server_and_after_a_restart() {
        let (setup, a) = setup_handler().await;
        insert_user_no_password(&a, "bob").await;
        let bob = UserId::new("bob");
        let proof = fresh_proof(&a, &bob).await;
        let b = SqlBackendHandler::new(setup.clone(), a.sql_pool.clone());
        b.start_totp_enrollment(&bob, None, Some(proof.clone()))
            .await
            .unwrap();
        let restarted = SqlBackendHandler::new(setup, a.sql_pool.clone());
        for (label, server) in [("the first server", &a), ("a restart", &restarted)] {
            let err = server
                .start_totp_enrollment(&bob, None, Some(proof.clone()))
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains(PASSWORD_PROOF_REQUIRED),
                "{label}: {err}"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_a_proof_is_refused_and_kept_when_its_table_cannot_answer() {
        let log = LogGuard::install_on_this_thread();
        let (_setup, handler) = setup_handler().await;
        insert_user_no_password(&handler, "bob").await;
        let bob = UserId::new("bob");
        let proof = fresh_proof(&handler, &bob).await;
        let rename = |from: &str, to: &str| {
            let sql = format!("ALTER TABLE {from} RENAME TO {to}");
            Statement::from_string(DbBackend::Sqlite, sql)
        };
        handler
            .sql_pool
            .execute(rename("mfa_used_proofs", "mfa_used_proofs_away"))
            .await
            .unwrap();
        let err = handler
            .start_totp_enrollment(&bob, None, Some(proof.clone()))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Password proof unreadable"),
            "{err}"
        );
        let rows: Vec<_> = log
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.kind == LogKind::MfaEnroll)
            .map(|e| (e.success, e.detail))
            .collect();
        assert_eq!(rows, vec![(false, Some("proof: unreadable".to_owned()))]);
        handler
            .sql_pool
            .execute(rename("mfa_used_proofs_away", "mfa_used_proofs"))
            .await
            .unwrap();
        handler
            .start_totp_enrollment(&bob, None, Some(proof))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_an_enrolled_user_gets_no_proof_and_a_replacement_ignores_one() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        let (bob, seed, _, current) = enroll_user(&handler, &setup, "bob").await;
        assert_eq!(handler.seal_enrollment_proof(&bob).await.unwrap(), None);

        let proof = seal_enrollment_proof(&ikm(&setup), "bob", now_unix()).unwrap();
        let err = handler
            .start_totp_enrollment(&bob, None, Some(proof.clone()))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(TOTP_CURRENT_CODE_REQUIRED),
            "{err}"
        );
        let err = handler
            .start_totp_enrollment(&bob, Some(wrong_code(&seed)), Some(proof.clone()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Invalid TOTP code"), "{err}");
        let restart = handler
            .start_totp_enrollment(&bob, Some(current), Some(proof.clone()))
            .await
            .unwrap();
        assert!(open_state(&setup, &restart.state).replaces_existing);

        handler
            .reset_user_mfa(&bob, MfaResetReason::Administrative)
            .await
            .unwrap();
        handler
            .start_totp_enrollment(&bob, None, Some(proof))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_start_totp_enrollment_requires_current_code() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        let (user_id, seed, _, current) = enroll_user(&handler, &setup, "bob").await;
        let sealed_before = get_mfa_columns(&handler, "bob").await.0.unwrap();

        let err = handler
            .start_totp_enrollment(&user_id, None, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(TOTP_CURRENT_CODE_REQUIRED));

        let err = handler
            .start_totp_enrollment(&user_id, Some(wrong_code(&seed)), None)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        assert_eq!(
            get_mfa_columns(&handler, "bob").await.0,
            Some(sealed_before)
        );

        let restart = handler
            .start_totp_enrollment(&user_id, Some(current), None)
            .await
            .unwrap();
        let new_state = open_state(&setup, &restart.state);
        assert!(new_state.replaces_existing);
        let (_, new_code) = current_code(&new_state.seed);
        handler
            .finish_totp_enrollment(&user_id, &restart.state, &new_code)
            .await
            .unwrap();
        let uuid = handler.get_user_model(&user_id).await.unwrap().uuid;
        let sealed_after = get_mfa_columns(&handler, "bob").await.0.unwrap();
        assert_eq!(
            open_totp_secret(&ikm(&setup), uuid.as_str(), &sealed_after).unwrap(),
            new_state.seed
        );
    }

    #[tokio::test]
    async fn test_reset_own_and_user_mfa() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        let (user_id, seed, _, current) = enroll_user(&handler, &setup, "bob").await;

        let err = handler
            .reset_own_mfa(&user_id, &wrong_code(&seed))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AuthenticationError(_)));
        assert!(get_mfa_columns(&handler, "bob").await.0.is_some());
        handler.reset_own_mfa(&user_id, &current).await.unwrap();
        assert_eq!(get_mfa_columns(&handler, "bob").await, (None, None));
        let err = handler.reset_own_mfa(&user_id, &current).await.unwrap_err();
        assert!(err.to_string().contains("not enrolled"));

        let (user_id, ..) = enroll_user(&handler, &setup, "eve").await;
        assert!(get_mfa_columns(&handler, "eve").await.0.is_some());
        handler
            .reset_user_mfa(&user_id, MfaResetReason::Administrative)
            .await
            .unwrap();
        assert_eq!(get_mfa_columns(&handler, "eve").await, (None, None));
        handler
            .reset_user_mfa(&user_id, MfaResetReason::Administrative)
            .await
            .unwrap();
        let err = handler
            .reset_user_mfa(&UserId::new("nobody"), MfaResetReason::Administrative)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::EntityNotFound(_)));
    }

    #[tokio::test]
    async fn test_verify_user_totp() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        let (user_id, seed, enroll_code, next_code) = enroll_user(&handler, &setup, "bob").await;
        insert_user_no_password(&handler, "john").await;

        assert_eq!(
            handler
                .verify_user_totp(&user_id, &enroll_code)
                .await
                .unwrap(),
            Err(TotpRejection::Replayed)
        );
        assert_eq!(
            handler
                .verify_user_totp(&user_id, &next_code)
                .await
                .unwrap(),
            Ok(())
        );
        assert_eq!(
            handler
                .verify_user_totp(&user_id, &next_code)
                .await
                .unwrap(),
            Err(TotpRejection::Replayed)
        );
        assert_eq!(
            handler
                .verify_user_totp(&user_id, &wrong_code(&seed))
                .await
                .unwrap(),
            Err(TotpRejection::Invalid)
        );
        assert_eq!(
            handler
                .verify_user_totp(&UserId::new("john"), &enroll_code)
                .await
                .unwrap(),
            Err(TotpRejection::NotEnrolled)
        );
        assert_eq!(
            handler
                .verify_user_totp(&UserId::new("nobody"), &enroll_code)
                .await
                .unwrap(),
            Err(TotpRejection::NotEnrolled)
        );

        for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
            let _ = handler.verify_user_totp(&user_id, &wrong_code(&seed)).await;
        }
        // A wrong code would report Invalid if the gate ran after verifying.
        assert_eq!(
            handler
                .verify_user_totp(&user_id, &wrong_code(&seed))
                .await
                .unwrap(),
            Err(TotpRejection::TooManyAttempts)
        );

        handler
            .write_mfa_columns(
                &user_id,
                Some(format!(
                    "{SEALED_PREFIX}{}",
                    "A".repeat(SEALED_BLOB_LEN - SEALED_PREFIX.len())
                )),
                Some(MFA_TYPE_TOTP.to_owned()),
            )
            .await
            .unwrap();
        assert_eq!(
            handler
                .verify_user_totp(&user_id, &next_code)
                .await
                .unwrap(),
            Err(TotpRejection::ReenrollmentRequired)
        );
    }

    async fn failures(handler: &SqlBackendHandler, user: &UserId) -> Vec<(i64, i16, bool)> {
        let found = model::TotpSteps::find()
            .filter(model::TotpStepsColumn::UserId.eq(user.clone()))
            .all(&handler.sql_pool)
            .await
            .unwrap();
        let mut rows: Vec<_> = found
            .into_iter()
            .map(|row| (row.step, row.failures, row.used))
            .collect();
        rows.sort_unstable();
        rows
    }

    #[tokio::test]
    #[serial]
    async fn test_a_new_key_takes_its_codes_in_the_steps_the_old_key_used() {
        let _clock = pin_clock(AT);
        let start = AT;
        let s = start / 30;
        let (setup, handler) = setup_handler().await;
        let (user_id, old_seed, ..) = enroll_user(&handler, &setup, "bob").await;
        let code = |seed: &[u8], at: i64| format_code(totp_code(seed, at as u64).unwrap());
        let old_key = get_mfa_columns(&handler, "bob").await.0.unwrap();
        set_enrollment_clock(Some(start + 30));
        let old_next = code(&old_seed, start + 30);
        let login = handler.verify_user_totp(&user_id, &old_next);
        assert_eq!(login.await.unwrap(), Ok(()));
        let current = Some(code(&old_seed, start + 60));
        let replacing = handler.start_totp_enrollment(&user_id, current, None);
        let replacing = replacing.await.unwrap();
        let new_seed = open_state(&setup, &replacing.state).seed;
        let marks = async || {
            let rows = failures(&handler, &user_id).await.into_iter();
            rows.filter(|row| row.2)
                .map(|row| row.0 - s)
                .collect::<Vec<_>>()
        };
        let finished = handler
            .finish_totp_enrollment(&user_id, &replacing.state, &code(&new_seed, start + 30))
            .await;
        let new_code = code(&new_seed, start + 60);
        let next = handler.verify_user_totp(&user_id, &new_code);
        let next = next.await.unwrap();
        let old_code = code(&old_seed, start);
        let stale = handler.verify_user_totp(&user_id, &old_code);
        let stale = stale.await.unwrap();
        let raced = mark_used(&handler.sql_pool, &user_id, s as u64, &old_key).await;
        assert_eq!(
            (finished.is_ok(), next, stale, raced.unwrap(), marks().await),
            (
                true,
                Ok(()),
                Err(TotpRejection::Invalid),
                Mark::KeyChanged,
                vec![1, 2]
            ),
            "the old key's marks go with it; its codes, even read before the change, mark nothing"
        );
        handler
            .reset_user_mfa(&user_id, MfaResetReason::Administrative)
            .await
            .unwrap();
        let cleared = marks().await;
        let proof = fresh_proof(&handler, &user_id).await;
        let again = handler.start_totp_enrollment(&user_id, None, Some(proof));
        let again = again.await.unwrap();
        let third_seed = open_state(&setup, &again.state).seed;
        let third = code(&third_seed, start + 60);
        let enrolled = handler.finish_totp_enrollment(&user_id, &again.state, &third);
        let enrolled = enrolled.await;
        assert_eq!(
            (cleared, enrolled.is_ok(), marks().await),
            (vec![], true, vec![2]),
            "a reset clears the marks; the next key's first code is taken in a step used before"
        );
    }

    #[tokio::test]
    async fn test_an_enrolment_state_holds_only_against_the_factor_it_was_minted_from() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        let (bob, old_seed, ..) = enroll_user(&handler, &setup, "bob").await;
        let code = |seed: &[u8], at: i64| format_code(totp_code(seed, at as u64).unwrap());
        let stale = |finished: &Result<()>| {
            finished
                .as_ref()
                .is_err_and(|e| e.to_string().contains("changed during enrollment"))
        };
        let current = Some(code(&old_seed, AT + 30));
        let replacing = handler.start_totp_enrollment(&bob, current, None).await;
        let replacing = replacing.unwrap().state;
        let seed = open_state(&setup, &replacing).seed;
        let (confirm, next) = (code(&seed, AT), code(&seed, AT + 30));
        let first = handler.finish_totp_enrollment(&bob, &replacing, &confirm);
        let first = first.await;
        set_enrollment_clock(Some(AT + 30));
        let signed_in = handler.verify_user_totp(&bob, &next).await;
        let again = handler.finish_totp_enrollment(&bob, &replacing, &confirm);
        let again = again.await;
        let reused = handler.verify_user_totp(&bob, &next).await;
        assert_eq!(
            (
                first.is_ok(),
                signed_in.unwrap(),
                stale(&again),
                reused.unwrap()
            ),
            (true, Ok(()), true, Err(TotpRejection::Replayed)),
            "a second finish of one state meets the factor its first wrote; a used code stays used"
        );

        set_enrollment_clock(Some(AT + 60));
        let mut states = Vec::new();
        for at in [AT + 60, AT + 90] {
            let current = Some(code(&seed, at));
            let started = handler.start_totp_enrollment(&bob, current, None).await;
            states.push(started.unwrap().state);
        }
        let mut finished = Vec::new();
        for state in &states {
            let confirm = code(&open_state(&setup, state).seed, AT + 60);
            let done = handler.finish_totp_enrollment(&bob, state, &confirm);
            finished.push(done.await);
        }
        assert_eq!(
            (finished[0].is_ok(), stale(&finished[1])),
            (true, true),
            "two replacement states from one factor: only the first finishes"
        );

        insert_user_no_password(&handler, "eve").await;
        let eve = UserId::new("eve");
        let mut states = Vec::new();
        for _ in 0..2 {
            let proof = Some(fresh_proof(&handler, &eve).await);
            let started = handler.start_totp_enrollment(&eve, None, proof).await;
            states.push(started.unwrap().state);
        }
        let mut finished = Vec::new();
        for state in &states {
            let confirm = code(&open_state(&setup, state).seed, AT + 60);
            let done = handler.finish_totp_enrollment(&eve, state, &confirm);
            finished.push(done.await);
        }
        assert_eq!(
            (finished[0].is_ok(), stale(&finished[1])),
            (true, true),
            "a first enrolment's state, after another enrolment finished: refused"
        );
    }

    fn code_of(seed: &[u8], at: i64) -> String {
        format_code(totp_code(seed, at as u64).unwrap())
    }

    /// An enrolled user and one replacement state, minted at `AT` from the user's factor.
    async fn minted_replacement(
        handler: &SqlBackendHandler,
        setup: &ServerSetup,
        user: &str,
    ) -> (UserId, String, [u8; TOTP_SEED_LEN]) {
        let (user, old_seed, ..) = enroll_user(handler, setup, user).await;
        let current = Some(code_of(&old_seed, AT + 30));
        let started = handler.start_totp_enrollment(&user, current, None).await;
        let state = started.unwrap().state;
        let seed = open_state(setup, &state).seed;
        (user, state, seed)
    }

    fn refused_as_stale(finished: &Result<()>) -> bool {
        finished
            .as_ref()
            .is_err_and(|e| e.to_string().contains("changed during enrollment"))
    }

    async fn marked_steps(handler: &SqlBackendHandler, user: &UserId) -> Vec<i64> {
        let rows = failures(handler, user).await.into_iter();
        rows.filter(|row| row.2).map(|row| row.0).collect()
    }

    /// Two finishes of one replacement state at once, on two connections.
    pub(crate) async fn finish_race_lane(pool: &DbConnection) {
        let _clock = pin_clock(AT);
        init_table(pool).await.expect("init");
        let setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(setup.clone(), pool.clone());
        let (user, state, seed) = minted_replacement(&handler, &setup, "e1brace").await;
        let steps = [AT, AT + 30];
        let finishes: Vec<_> = steps
            .iter()
            .map(|at| {
                let confirm = code_of(&seed, *at);
                let (handler, user, state) = (handler.clone(), user.clone(), state.clone());
                tokio::spawn(async move {
                    handler
                        .finish_totp_enrollment(&user, &state, &confirm)
                        .await
                })
            })
            .collect();
        let mut answers = Vec::new();
        for finish in finishes {
            answers.push(finish.await.unwrap());
        }
        let won: Vec<i64> = steps
            .iter()
            .zip(&answers)
            .filter(|(_, answer)| answer.is_ok())
            .map(|(at, _)| at / 30)
            .collect();
        let refused = answers
            .iter()
            .filter(|answer| refused_as_stale(answer))
            .count();
        let stored = get_mfa_columns(&handler, "e1brace").await.0.unwrap();
        let uuid = handler.get_user_model(&user).await.unwrap().uuid;
        let opened = open_totp_secret(&ikm(&setup), uuid.as_str(), &stored).unwrap();
        assert_eq!(
            (
                won.len(),
                refused,
                opened == seed,
                marked_steps(&handler, &user).await == won
            ),
            (1, 1, true, true),
            "one finishes, the other is stale; the factor is the winner's, and so is the one mark"
        );
    }

    /// A finish meeting another finish held open before its commit waits, then is stale.
    pub(crate) async fn finish_held_lane(pool: &DbConnection) {
        let _clock = pin_clock(AT);
        init_table(pool).await.expect("init");
        let setup = generate_random_private_key();
        let handler = SqlBackendHandler::new(setup.clone(), pool.clone());
        let (user, state, seed) = minted_replacement(&handler, &setup, "e1bheld").await;
        let backend = pool.get_database_backend();
        let name = Value::from(user.as_str().to_owned());
        let held = pool.begin().await.unwrap();
        let sql = "SELECT totp_secret FROM users WHERE user_id = ? FOR UPDATE";
        let lock = Statement::from_sql_and_values(backend, numbered(backend, sql), [name.clone()]);
        held.query_one(lock).await.unwrap();
        let sql = numbered(
            backend,
            "UPDATE users SET totp_secret = ? WHERE user_id = ?",
        );
        let values = [Value::from("v1.held".to_owned()), name];
        held.execute(Statement::from_sql_and_values(backend, sql, values))
            .await
            .unwrap();
        let finish = {
            let confirm = code_of(&seed, AT);
            let (handler, user) = (handler.clone(), user.clone());
            tokio::spawn(async move {
                handler
                    .finish_totp_enrollment(&user, &state, &confirm)
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let waited = !finish.is_finished();
        held.commit().await.unwrap();
        let answer = finish.await.unwrap();
        assert_eq!(
            (waited, refused_as_stale(&answer)),
            (true, true),
            "the finish waits on the user's row, then meets the factor the held one wrote"
        );
    }

    #[tokio::test]
    async fn test_one_states_second_finish_after_the_first_is_stale_on_sqlites_one_connection() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        let (user, state, seed) = minted_replacement(&handler, &setup, "bob").await;
        let (first, second) = (code_of(&seed, AT), code_of(&seed, AT + 30));
        let finished = handler.finish_totp_enrollment(&user, &state, &first).await;
        let again = handler.finish_totp_enrollment(&user, &state, &second).await;
        assert_eq!(
            (
                finished.is_ok(),
                refused_as_stale(&again),
                marked_steps(&handler, &user).await
            ),
            (true, true, vec![AT / 30]),
            "after the first finish committed, the second is stale and leaves the first's one mark"
        );
    }

    #[tokio::test]
    async fn test_a_code_is_refused_when_its_mark_or_its_refund_cannot_be_written() {
        let _clock = pin_clock(AT);
        let raise = "BEGIN SELECT RAISE(ABORT, 'refused'); END";
        for (label, trigger) in [
            ("the mark", "BEFORE INSERT ON totp_steps WHEN NEW.used"),
            (
                "the refund",
                "BEFORE UPDATE OF failures ON totp_steps WHEN NEW.failures < OLD.failures",
            ),
        ] {
            let (setup, handler) = setup_handler().await;
            let (user_id, _, _, next) = enroll_user(&handler, &setup, "bob").await;
            let sql = format!("CREATE TRIGGER e1b_refused {trigger} {raise}");
            let create = Statement::from_string(DbBackend::Sqlite, sql);
            handler.sql_pool.execute(create).await.unwrap();
            assert_eq!(
                handler.verify_user_totp(&user_id, &next).await.unwrap(),
                Err(TotpRejection::Unreadable),
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn test_a_code_is_refused_when_its_table_cannot_answer() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        let (user_id, _, _, next) = enroll_user(&handler, &setup, "bob").await;
        let drop = Statement::from_string(DbBackend::Sqlite, "DROP TABLE totp_steps".to_owned());
        handler.sql_pool.execute(drop).await.unwrap();
        assert_eq!(
            handler.verify_user_totp(&user_id, &next).await.unwrap(),
            Err(TotpRejection::Unreadable)
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_two_servers_and_a_restart_share_the_attempts_and_the_used_codes() {
        let _clock = pin_clock(AT);
        let start = AT;
        let (setup, a) = setup_handler().await;
        let b = SqlBackendHandler::new(setup.clone(), a.sql_pool.clone());
        let (user_id, seed, ..) = enroll_user(&a, &setup, "bob").await;
        let code = |at: i64| format_code(totp_code(&seed, at as u64).unwrap());
        set_enrollment_clock(Some(start + 30));
        for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
            assert_eq!(
                a.verify_user_totp(&user_id, &wrong_code(&seed))
                    .await
                    .unwrap(),
                Err(TotpRejection::Invalid)
            );
        }
        let restarted = SqlBackendHandler::new(setup.clone(), a.sql_pool.clone());
        assert_eq!(
            (
                b.verify_user_totp(&user_id, &code(start + 30))
                    .await
                    .unwrap(),
                restarted
                    .verify_user_totp(&user_id, &code(start + 30))
                    .await
                    .unwrap()
            ),
            (
                Err(TotpRejection::TooManyAttempts),
                Err(TotpRejection::TooManyAttempts)
            ),
            "five wrong on one server: the right code is refused on another and after a restart"
        );
        set_enrollment_clock(Some(start + 60));
        let right = code(start + 60);
        assert_eq!(
            (
                b.verify_user_totp(&user_id, &right).await.unwrap(),
                a.verify_user_totp(&user_id, &right).await.unwrap(),
                restarted.verify_user_totp(&user_id, &right).await.unwrap()
            ),
            (
                Ok(()),
                Err(TotpRejection::Replayed),
                Err(TotpRejection::Replayed)
            ),
            "the next step allows the code once, on any server"
        );
        set_enrollment_clock(Some(start + 90));
        for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP - 1 {
            let _ = a.verify_user_totp(&user_id, &wrong_code(&seed)).await;
        }
        let used_before = b.verify_user_totp(&user_id, &right).await.unwrap();
        let fresh = b
            .verify_user_totp(&user_id, &code(start + 90))
            .await
            .unwrap();
        let last = a
            .verify_user_totp(&user_id, &wrong_code(&seed))
            .await
            .unwrap();
        let spent = a
            .verify_user_totp(&user_id, &wrong_code(&seed))
            .await
            .unwrap();
        assert_eq!(
            (used_before, fresh, last, spent),
            (
                Err(TotpRejection::Replayed),
                Ok(()),
                Err(TotpRejection::Invalid),
                Err(TotpRejection::TooManyAttempts)
            ),
            "a right code and a used one give their attempts back; the fifth wrong one is the last"
        );
        let step = |at: i64| at / 30;
        assert_eq!(
            failures(&a, &user_id).await.last(),
            Some(&(
                step(start + 90),
                i16::from(TOTP_MAX_ATTEMPTS_PER_STEP),
                true
            ))
        );
    }

    #[tokio::test]
    async fn test_clear_all_mfa() {
        let _clock = pin_clock(AT);
        let (setup, handler) = setup_handler().await;
        enroll_user(&handler, &setup, "bob").await;
        enroll_user(&handler, &setup, "eve").await;
        insert_user_no_password(&handler, "john").await;

        assert_eq!(handler.clear_all_mfa().await.unwrap(), 2);
        for user in ["bob", "eve", "john"] {
            assert_eq!(get_mfa_columns(&handler, user).await, (None, None));
        }
        assert_eq!(handler.clear_all_mfa().await.unwrap(), 0);
    }

    #[tokio::test]
    #[serial]
    async fn test_mfa_log_rows() {
        let _clock = pin_clock(AT);
        let guard = LogGuard::install();
        let peer = "10.77.0.1";
        let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
        with_request(meta, async {
            let (setup, handler) = setup_handler().await;
            let (bob, seed, _, next) = enroll_user(&handler, &setup, "bob").await;
            assert!(
                handler
                    .reset_own_mfa(&bob, &wrong_code(&seed))
                    .await
                    .is_err()
            );
            handler.reset_own_mfa(&bob, &next).await.unwrap();
            handler
                .reset_user_mfa(&bob, MfaResetReason::Administrative)
                .await
                .unwrap();
            let (kim, ..) = enroll_user(&handler, &setup, "kim").await;
            handler
                .reset_user_mfa(&kim, MfaResetReason::PasswordReset)
                .await
                .unwrap();
            enroll_user(&handler, &setup, "eve").await;
            handler.clear_all_mfa().await.unwrap();

            // Every rejection of the enrollment ceremony has its own detail.
            let (setup, handler) = setup_handler().await;
            insert_user_no_password(&handler, "bob").await;
            insert_user_no_password(&handler, "john").await;
            let bob = UserId::new("bob");
            let _ = handler.start_totp_enrollment(&bob, None, None).await;
            let proof = fresh_proof(&handler, &bob).await;
            let start = handler
                .start_totp_enrollment(&bob, None, Some(proof))
                .await
                .unwrap();
            let state = open_state(&setup, &start.state);
            let (now, code) = current_code(&state.seed);
            let _ = handler
                .finish_totp_enrollment(&bob, &start.state, &wrong_code(&state.seed))
                .await;
            let expired = lldap_mfa::seal_enrollment(
                &ikm(&setup),
                "bob",
                &state.seed,
                None,
                now as i64 - TOTP_ENROLLMENT_TTL_SECS as i64 - 1,
            )
            .unwrap();
            let _ = handler.finish_totp_enrollment(&bob, &expired, &code).await;
            let _ = handler
                .finish_totp_enrollment(&bob, "not-a-sealed-state", &code)
                .await;
            let _ = handler
                .finish_totp_enrollment(&UserId::new("john"), &start.state, &code)
                .await;
            let replacing = lldap_mfa::seal_enrollment(
                &ikm(&setup),
                "bob",
                &state.seed,
                Some("v1.another"),
                now as i64,
            )
            .unwrap();
            let _ = handler
                .finish_totp_enrollment(&bob, &replacing, &code)
                .await;
            handler
                .finish_totp_enrollment(&bob, &start.state, &code)
                .await
                .unwrap();
            let err = handler
                .start_totp_enrollment(&bob, None, None)
                .await
                .unwrap_err();
            assert!(err.to_string().contains(TOTP_CURRENT_CODE_REQUIRED));
            let _ = handler
                .start_totp_enrollment(&bob, Some(wrong_code(&state.seed)), None)
                .await;
        })
        .await;

        let rows: Vec<(LogKind, bool, Option<String>, Option<String>)> = guard
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.peer.as_deref() == Some(peer))
            .filter(|e| matches!(e.kind, LogKind::MfaEnroll | LogKind::MfaReset))
            .map(|e| (e.kind, e.success, e.target, e.detail))
            .collect();
        let row = |kind, success, target: &str, detail: &str| {
            (
                kind,
                success,
                Some(target.to_owned()),
                Some(detail.to_owned()),
            )
        };
        assert_eq!(
            rows,
            vec![
                row(LogKind::MfaEnroll, true, "bob", "started"),
                row(LogKind::MfaEnroll, true, "bob", "totp"),
                row(LogKind::MfaReset, false, "bob", "invalid totp"),
                row(LogKind::MfaReset, true, "bob", "self"),
                row(LogKind::MfaEnroll, true, "kim", "started"),
                row(LogKind::MfaEnroll, true, "kim", "totp"),
                row(LogKind::MfaReset, true, "kim", "password reset"),
                row(LogKind::MfaEnroll, true, "eve", "started"),
                row(LogKind::MfaEnroll, true, "eve", "totp"),
                (
                    LogKind::MfaReset,
                    true,
                    None,
                    Some("private key changed".to_owned())
                ),
                row(LogKind::MfaEnroll, false, "bob", "password proof required"),
                row(LogKind::MfaEnroll, true, "bob", "started"),
                row(LogKind::MfaEnroll, false, "bob", "invalid code"),
                row(LogKind::MfaEnroll, false, "bob", "expired enrollment"),
                row(LogKind::MfaEnroll, false, "bob", "corrupt enrollment state"),
                row(
                    LogKind::MfaEnroll,
                    false,
                    "john",
                    "foreign enrollment state"
                ),
                row(LogKind::MfaEnroll, false, "bob", "stale enrollment"),
                row(LogKind::MfaEnroll, true, "bob", "totp"),
                row(LogKind::MfaEnroll, false, "bob", "invalid totp"),
            ]
        );
    }
}
