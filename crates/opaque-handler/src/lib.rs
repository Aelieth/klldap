#![forbid(unsafe_code)]
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use lldap_domain::types::{LoginOutcome, UserId};
use lldap_domain_model::error::{DomainError, Result};
use tokio::sync::Semaphore;

use lldap_auth::opaque;
pub use lldap_auth::{login, registration};

pub const STRETCH_FAILED: &str = "OPAQUE key stretching did not complete";

static STRETCH: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));

async fn stretch_on<T: Send + 'static>(
    permits: Arc<Semaphore>,
    work: impl FnOnce() -> T + Send + 'static,
) -> std::result::Result<T, tokio::task::JoinError> {
    let permit = permits
        .acquire_owned()
        .await
        .expect("the stretch semaphore is not closed");
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
}

pub async fn stretch<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> std::result::Result<T, tokio::task::JoinError> {
    stretch_on(Arc::clone(&STRETCH), work).await
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
}

/// Runs the OPAQUE registration ceremony in-process, playing the client against `handler`.
pub async fn register_password(
    handler: &(impl OpaqueHandler + ?Sized),
    username: UserId,
    password: &[u8],
) -> Result<()> {
    let mut rng = rand::rngs::OsRng;
    let registration_start = opaque::client::registration::start_registration(password, &mut rng)?;
    let start_response = handler
        .registration_start(registration::ClientRegistrationStartRequest {
            username,
            registration_start_request: registration_start.message,
        })
        .await?;
    let password = password.to_vec();
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
    handler
        .registration_finish(registration::ClientRegistrationFinishRequest {
            server_data: start_response.server_data,
            registration_upload: registration_finish.message,
        })
        .await
        .map(|_| ())
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
}
