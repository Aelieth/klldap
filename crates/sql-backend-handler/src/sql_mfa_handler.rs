use crate::SqlBackendHandler;
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
    ENROLLMENT_PROOF_BUSY, MfaError, PASSWORD_PROOF_REQUIRED, ProofUse, TOTP_CODE_ALREADY_USED,
    TOTP_CURRENT_CODE_REQUIRED, TOTP_ENROLLMENT_EXPIRED, TOTP_TOO_MANY_ATTEMPTS, UsedProofs,
    open_enrollment_proof, seal_enrollment_proof,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, EntityTrait, QueryFilter, sea_query::Expr,
};
#[cfg(test)]
use std::cell::Cell;
use std::sync::OnceLock;
use tracing::{info, instrument, warn};

const TOTP_ISSUER: &str = "KLLDAP";

#[cfg(test)]
thread_local! {
    static TEST_NOW: Cell<Option<i64>> = const { Cell::new(None) };
}

#[cfg(test)]
fn set_enrollment_clock(now: Option<i64>) {
    TEST_NOW.with(|clock| clock.set(now));
}

fn now_unix() -> i64 {
    #[cfg(test)]
    if let Some(now) = TEST_NOW.with(|clock| clock.get()) {
        return now;
    }
    chrono::Utc::now().timestamp()
}

fn used_proofs() -> &'static UsedProofs {
    static USED: OnceLock<UsedProofs> = OnceLock::new();
    USED.get_or_init(UsedProofs::new)
}

fn refuse_proof(user_id: &UserId) -> DomainError {
    logging::record_failure(
        LogKind::MfaEnroll,
        Some(user_id.as_str()),
        "password proof required",
    );
    DomainError::AuthenticationError(PASSWORD_PROOF_REQUIRED.to_string())
}

fn take_proof(
    used: &UsedProofs,
    key: &[u8],
    user_id: &UserId,
    token: Option<&str>,
    now: i64,
) -> Result<()> {
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return Err(refuse_proof(user_id));
    };
    let Ok(proof) = open_enrollment_proof(key, token, now) else {
        return Err(refuse_proof(user_id));
    };
    if proof.user_id != user_id.as_str() {
        return Err(refuse_proof(user_id));
    }
    match used.mark_used(proof.id, proof.expiry_unix, now) {
        ProofUse::Accepted => Ok(()),
        ProofUse::Refused => Err(refuse_proof(user_id)),
        ProofUse::Full => {
            warn!(
                r#"First enrollment for "{}" refused: every used-proof slot holds a live proof"#,
                user_id
            );
            logging::record_failure(
                LogKind::MfaEnroll,
                Some(user_id.as_str()),
                "enrollment busy",
            );
            Err(DomainError::AuthenticationError(
                ENROLLMENT_PROOF_BUSY.to_owned(),
            ))
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
        }
    }

    pub(crate) fn into_error(self, user_id: &UserId) -> DomainError {
        DomainError::AuthenticationError(match self {
            Self::NotEnrolled => format!("User {user_id} is not enrolled in TOTP MFA"),
            Self::ReenrollmentRequired => format!("TOTP re-enrollment required for {user_id}"),
            Self::TooManyAttempts => format!("{TOTP_TOO_MANY_ATTEMPTS} for {user_id}"),
            Self::Invalid => format!("Invalid TOTP code for {user_id}"),
            Self::Replayed => format!("{TOTP_CODE_ALREADY_USED} for {user_id}"),
        })
    }
}

impl SqlBackendHandler {
    async fn get_user_model(&self, user_id: &UserId) -> Result<model::users::Model> {
        model::User::find_by_id(user_id.clone())
            .one(&self.sql_pool)
            .await?
            .ok_or_else(|| DomainError::EntityNotFound(user_id.to_string()))
    }

    // Both columns are always written together: no orphan sealed secrets.
    async fn write_mfa_columns(
        &self,
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
        user_update.update(&self.sql_pool).await?;
        Ok(())
    }

    // The TOTP secret, the enrollment state and the proof each derive their own key from it.
    fn sealing_key(&self) -> Vec<u8> {
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

    // Reserve before verifying, so a spent allowance cannot keep testing codes; a correct
    // code is refunded before the replay check, so a replay costs nothing.
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
        let now = now_unix();
        if !self.failed_totp_attempts.reserve(uuid, now as u64) {
            return Ok(Err(TotpRejection::TooManyAttempts));
        }
        if !lldap_mfa::totp_verify(&seed, code, now as u64)
            .map_err(|e| DomainError::InternalError(format!("TOTP verification failed: {e}")))?
        {
            return Ok(Err(TotpRejection::Invalid));
        }
        self.failed_totp_attempts.refund(uuid, now as u64);
        if !self.used_totp_codes.mark_used(uuid, code, now) {
            return Ok(Err(TotpRejection::Replayed));
        }
        Ok(Ok(()))
    }

    /// Every sealed secret dies with the server key; one system row records the sweep.
    pub async fn clear_all_mfa(&self) -> Result<u64> {
        let cleared = model::User::update_many()
            .col_expr(UserColumn::TotpSecret, Expr::value(None::<String>))
            .col_expr(UserColumn::MfaType, Expr::value(None::<String>))
            .col_expr(
                UserColumn::ModifiedDate,
                Expr::value(chrono::Utc::now().naive_utc()),
            )
            .filter(UserColumn::MfaType.is_not_null())
            .exec(&self.sql_pool)
            .await?
            .rows_affected;
        if cleared > 0 {
            logging::record(LogKind::MfaReset, None, Some("private key changed"));
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
        let replaces_existing = self.get_user_model(user_id).await?.mfa_type.is_some();
        if !replaces_existing {
            let token = enrollment_proof.as_deref();
            take_proof(
                used_proofs(),
                &self.sealing_key(),
                user_id,
                token,
                now_unix(),
            )?;
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
            replaces_existing,
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
        if !lldap_mfa::totp_verify(&state.seed, code, now as u64)
            .map_err(|e| DomainError::InternalError(format!("TOTP verification failed: {e}")))?
        {
            return Err(refuse(
                "invalid code",
                DomainError::AuthenticationError(format!("Invalid TOTP code for {user_id}")),
            ));
        }
        let user = self.get_user_model(user_id).await?;
        // The gate ran at enrollment start, so the factor must not have moved since.
        if state.replaces_existing != user.mfa_type.is_some() {
            return Err(refuse(
                "stale enrollment",
                DomainError::AuthenticationError(format!(
                    "Two-factor changed during enrollment for {user_id}"
                )),
            ));
        }
        if !self
            .used_totp_codes
            .mark_used(user.uuid.as_str(), code, now)
        {
            return Err(refuse(
                TotpRejection::Replayed.detail(),
                TotpRejection::Replayed.into_error(user_id),
            ));
        }
        let sealed =
            lldap_mfa::seal_totp_secret(&self.sealing_key(), user.uuid.as_str(), &state.seed)
                .map_err(|e| {
                    DomainError::InternalError(format!("Could not seal TOTP secret: {e}"))
                })?;
        self.write_mfa_columns(user_id, Some(sealed), Some(MFA_TYPE_TOTP.to_owned()))
            .await?;
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
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::{get_initialized_db, insert_user_no_password};
    use lldap_auth::opaque::server::{ServerSetup, generate_random_private_key};
    use lldap_domain_handlers::logging::{RequestMeta, with_request, with_request_sync};
    use lldap_mfa::{
        EnrollmentState, SEALED_BLOB_LEN, SEALED_PREFIX, TOTP_CURRENT_CODE_REQUIRED,
        TOTP_ENROLLMENT_TTL_SECS, TOTP_MAX_ATTEMPTS_PER_STEP, TOTP_SEED_LEN, TOTP_STEP_SECS,
        format_code, open_totp_secret, seed_base32, totp_code,
    };
    use lldap_test_utils::recording_log::LogGuard;
    use pretty_assertions::assert_eq;
    use serial_test::serial;

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
            lldap_mfa::seal_enrollment(&ikm(&setup), "bob", &state.seed, false, stale).unwrap();
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
        let replacing =
            lldap_mfa::seal_enrollment(&ikm(&setup), "bob", &state.seed, true, now as i64).unwrap();
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
    async fn test_proof_opens_on_a_second_handler_with_the_same_key() {
        let (setup, handler) = setup_handler().await;
        insert_user_no_password(&handler, "bob").await;
        let bob = UserId::new("bob");
        let proof = fresh_proof(&handler, &bob).await;
        let other = SqlBackendHandler::new(setup, handler.sql_pool.clone());
        other
            .start_totp_enrollment(&bob, None, Some(proof))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_an_enrolled_user_gets_no_proof_and_a_replacement_ignores_one() {
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

    #[derive(Clone, Default)]
    struct Warnings(std::sync::Arc<std::sync::Mutex<usize>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let meta = event.metadata();
            if *meta.level() == tracing::Level::WARN
                && meta.target() == "lldap_sql_backend_handler::sql_mfa_handler"
            {
                *self.0.lock().unwrap() += 1;
            }
        }
    }

    fn filler_id(n: u32) -> [u8; 16] {
        let mut id = [0xffu8; 16];
        id[12..].copy_from_slice(&n.to_be_bytes());
        id
    }

    #[tokio::test]
    #[serial]
    async fn test_a_full_used_proof_set_refuses_a_first_enrollment_and_keeps_its_proof() {
        use tracing_subscriber::layer::SubscriberExt;
        let guard = LogGuard::install();
        let peer = "10.77.0.2";
        let (setup, _handler) = setup_handler().await;
        let key = ikm(&setup);
        let bob = UserId::new("bob");
        let now = 1_700_000_000;
        let used = UsedProofs::new();
        let mut fillers = 0u32;
        while used.mark_used(filler_id(fillers), now + 10, now) == ProofUse::Accepted {
            fillers += 1;
            assert!(fillers < 100_000, "the used-proof set never filled");
        }
        let proof = seal_enrollment_proof(&key, "bob", now).unwrap();
        let warnings = Warnings::default();
        let subscriber = tracing_subscriber::registry().with(warnings.clone());
        let meta = RequestMeta::http(Some(peer.parse().unwrap()), None);
        let answers = with_request_sync(meta, || {
            tracing::subscriber::with_default(subscriber, || {
                [now, now + 11, now + 11].map(|at| {
                    take_proof(&used, &key, &bob, Some(&proof), at).map_err(|e| e.to_string())
                })
            })
        });
        let [busy, accepted, again] = answers;
        assert!(
            busy.as_ref().unwrap_err().contains(ENROLLMENT_PROOF_BUSY),
            "{busy:?}"
        );
        assert_eq!(
            accepted,
            Ok(()),
            "the refused start did not spend the proof"
        );
        assert!(
            again
                .as_ref()
                .unwrap_err()
                .contains(PASSWORD_PROOF_REQUIRED),
            "{again:?}"
        );
        assert_eq!(*warnings.0.lock().unwrap(), 1);
        let rows: Vec<(bool, Option<String>)> = guard
            .recorder()
            .take_events()
            .into_iter()
            .filter(|e| e.peer.as_deref() == Some(peer) && e.kind == LogKind::MfaEnroll)
            .map(|e| (e.success, e.detail))
            .collect();
        assert_eq!(
            rows,
            vec![
                (false, Some("enrollment busy".to_owned())),
                (false, Some("password proof required".to_owned())),
            ]
        );
    }

    #[tokio::test]
    async fn test_start_totp_enrollment_requires_current_code() {
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

        // Spend the next step too, or a boundary crossed mid-test refills the allowance.
        // It goes first: reserving prunes older steps, dropping the wrong codes below.
        let uuid = handler.get_user_model(&user_id).await.unwrap().uuid;
        let next_step = now_unix() as u64 + TOTP_STEP_SECS;
        for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
            assert!(
                handler
                    .failed_totp_attempts
                    .reserve(uuid.as_str(), next_step)
            );
        }
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

    #[tokio::test]
    async fn test_clear_all_mfa() {
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
                false,
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
            let replacing =
                lldap_mfa::seal_enrollment(&ikm(&setup), "bob", &state.seed, true, now as i64)
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
