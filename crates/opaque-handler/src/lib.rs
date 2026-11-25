#![forbid(unsafe_code)]
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use lldap_domain::types::{LoginOutcome, UserId};
use lldap_domain_model::error::{DomainError, Result};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinError;

use lldap_auth::opaque;
pub use lldap_auth::{login, registration};

pub const STRETCH_FAILED: &str = "OPAQUE key stretching did not complete";
pub const STRETCH_BUSY: &str = "too many sign-ins are waiting for key stretching; try again";

static STRETCH: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));

async fn run_with<T: Send + 'static>(
    permit: OwnedSemaphorePermit,
    work: impl FnOnce() -> T + Send + 'static,
) -> std::result::Result<T, JoinError> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
}

async fn stretch_on<T: Send + 'static>(
    permits: Arc<Semaphore>,
    work: impl FnOnce() -> T + Send + 'static,
) -> std::result::Result<T, JoinError> {
    let permit = permits
        .acquire_owned()
        .await
        .expect("the stretch semaphore is not closed");
    run_with(permit, work).await
}

pub async fn stretch<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> std::result::Result<T, JoinError> {
    stretch_on(Arc::clone(&STRETCH), work).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StretchError {
    /// No place to wait was free, or no permit came within the wait: the work never started.
    Busy,
    Failed,
}

pub struct StretchGate {
    permits: Arc<Semaphore>,
    waiting: Semaphore,
    wait: Duration,
}

impl StretchGate {
    pub fn new(waiters: usize, wait: Duration) -> Self {
        Self::on(Arc::clone(&STRETCH), waiters, wait)
    }

    pub fn on(permits: Arc<Semaphore>, waiters: usize, wait: Duration) -> Self {
        Self {
            permits,
            waiting: Semaphore::new(waiters),
            wait,
        }
    }

    pub async fn stretch<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> std::result::Result<T, StretchError> {
        let Ok(place) = self.waiting.try_acquire() else {
            return Err(StretchError::Busy);
        };
        let permit = Arc::clone(&self.permits).acquire_owned();
        let permit = tokio::time::timeout(self.wait, permit).await;
        drop(place);
        let Ok(Ok(permit)) = permit else {
            return Err(StretchError::Busy);
        };
        let done = run_with(permit, work).await;
        done.map_err(|_| StretchError::Failed)
    }
}

#[async_trait]
pub trait OpaqueHandler: Send + Sync {
    async fn login_start(
        &self,
        request: login::ClientLoginStartRequest,
    ) -> Result<login::ServerLoginStartResponse>;
    async fn login_finish(&self, request: login::ClientLoginFinishRequest) -> Result<LoginOutcome>;
    async fn registration_start(
        &self,
        request: registration::ClientRegistrationStartRequest,
    ) -> Result<registration::ServerRegistrationStartResponse>;
    async fn registration_finish(
        &self,
        request: registration::ClientRegistrationFinishRequest,
    ) -> Result<UserId>;
    /// A web or tool start: its server data also seals who made it and the envelope key answered.
    async fn registration_start_by(
        &self,
        request: registration::ClientRegistrationStartRequest,
        by: registration::Presenter,
        envelope_key: Option<[u8; 32]>,
    ) -> Result<registration::ServerRegistrationStartResponse>;
    /// A web or tool finish, taken once, in time, and only from the session that made its start.
    async fn registration_claim(
        &self,
        request: &registration::ClientRegistrationFinishRequest,
        presenter: &registration::Presenter,
    ) -> Result<registration::Claim>;
}

/// Runs the OPAQUE registration ceremony in-process, playing the client against `handler`.
pub async fn register_password(
    handler: &(impl OpaqueHandler + ?Sized),
    username: UserId,
    password: &[u8],
) -> Result<()> {
    let (_, request) = prepare_registration(handler, username, password).await?;
    handler.registration_finish(request).await.map(|_| ())
}

/// The ceremony up to its one write, `registration_finish(request)`. The record that write
/// stores is returned beside the request.
pub async fn prepare_registration(
    handler: &(impl OpaqueHandler + ?Sized),
    username: UserId,
    password: &[u8],
) -> Result<(Vec<u8>, registration::ClientRegistrationFinishRequest)> {
    let mut rng = rand::rngs::OsRng;
    let registration_start = opaque::client::registration::start_registration(password, &mut rng)?;
    let start_response = handler
        .registration_start(registration::ClientRegistrationStartRequest {
            username,
            registration_start_request: registration_start.message,
        })
        .await?;
    let password = zeroize::Zeroizing::new(password.to_vec());
    let registration_finish = stretch(move || {
        opaque::client::registration::finish_registration(
            registration_start.state,
            &password,
            start_response.registration_response,
            &mut rand::rngs::OsRng,
        )
    })
    .await
    .map_err(|_| DomainError::InternalError(STRETCH_FAILED.to_string()))??;
    let password_file =
        opaque::server::registration::get_password_file(registration_finish.message.clone())
            .serialize()
            .to_vec();
    Ok((
        password_file,
        registration::ClientRegistrationFinishRequest {
            server_data: start_response.server_data,
            registration_upload: registration_finish.message,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn four_permits_hold_the_fifth_until_one_is_released() {
        let permits = Arc::new(Semaphore::new(4));
        let entered = Arc::new(AtomicUsize::new(0));
        let release = Arc::new((Mutex::new(0usize), Condvar::new()));
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let permits = Arc::clone(&permits);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            tasks.push(tokio::spawn(async move {
                stretch_on(Arc::clone(&permits), move || {
                    entered.fetch_add(1, Ordering::SeqCst);
                    let (lock, cv) = &*release;
                    let mut left = lock.lock().expect("release lock");
                    while *left == 0 {
                        left = cv.wait(left).expect("release wait");
                    }
                    *left -= 1;
                })
                .await
                .expect("stretch");
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while entered.load(Ordering::SeqCst) < 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("four entered");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(entered.load(Ordering::SeqCst), 4);
        {
            let (lock, cv) = &*release;
            *lock.lock().expect("release") = 1;
            cv.notify_one();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while entered.load(Ordering::SeqCst) < 5 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fifth entered");
        {
            let (lock, cv) = &*release;
            *lock.lock().expect("release") = 4;
            cv.notify_all();
        }
        for task in tasks {
            task.await.expect("task");
        }
    }

    #[tokio::test]
    async fn a_dropped_caller_keeps_its_permit() {
        let permits = Arc::new(Semaphore::new(4));
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let permits_for_call = Arc::clone(&permits);
        let call = tokio::spawn(async move {
            stretch_on(Arc::clone(&permits_for_call), move || {
                started_tx.send(()).expect("started");
                let _ = release_rx.recv();
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if started_rx.try_recv().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the closure started");
        call.abort();
        tokio::task::yield_now().await;
        assert_eq!(permits.available_permits(), 3);
        release_tx.send(()).expect("release");
        tokio::time::timeout(Duration::from_secs(2), async {
            while permits.available_permits() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("permit returned");
    }

    fn with_no_permit(waiters: usize, wait: Duration) -> StretchGate {
        StretchGate::on(Arc::new(Semaphore::new(0)), waiters, wait)
    }

    #[tokio::test]
    async fn the_waiter_past_the_last_place_is_turned_away_at_once() {
        let gate = Arc::new(with_no_permit(32, Duration::from_secs(60)));
        let mut waiting = Vec::new();
        for _ in 0..32 {
            let gate = Arc::clone(&gate);
            waiting.push(tokio::spawn(async move { gate.stretch(|| ()).await }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while gate.waiting.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("thirty-two wait");
        let asked = std::time::Instant::now();
        let turned_away = gate.stretch(|| ()).await;
        let at_once = asked.elapsed() < Duration::from_secs(1);
        waiting.iter().for_each(|waiter| waiter.abort());
        assert_eq!((turned_away, at_once), (Err(StretchError::Busy), true));
    }

    #[tokio::test]
    async fn a_waiter_is_given_up_at_the_wait_and_its_work_never_starts() {
        let wait = Duration::from_millis(50);
        let gate = with_no_permit(1, wait);
        let started = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&started);
        let asked = std::time::Instant::now();
        let work = move || counted.fetch_add(1, Ordering::SeqCst);
        let given_up = gate.stretch(work).await;
        let waited = asked.elapsed();
        assert_eq!(
            (
                given_up,
                started.load(Ordering::SeqCst),
                gate.waiting.available_permits()
            ),
            (Err(StretchError::Busy), 0, 1)
        );
        let bound = (waited >= wait, waited < Duration::from_secs(2));
        assert_eq!(bound, (true, true), "{waited:?}");
    }

    #[tokio::test]
    async fn work_that_starts_and_does_not_complete_is_failed_and_returns_its_permit() {
        let gate = StretchGate::on(Arc::new(Semaphore::new(1)), 1, Duration::from_secs(2));
        let stopped = gate.stretch(|| -> u8 { panic!("stopped") }).await;
        assert_eq!(
            (stopped, gate.stretch(|| 7_u8).await),
            (Err(StretchError::Failed), Ok(7))
        );
    }
}
