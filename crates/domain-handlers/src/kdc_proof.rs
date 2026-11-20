use crate::enforcement::{
    Entries, PolicyCache, UserFacts, cached_mfa_policy, mfa_can_be_on, user_written,
};
use crate::handler::{PolicyBackendHandler, UserBackendHandler};
use crate::mfa::{MfaEnrollmentStatus, MfaPolicy, MfaRequirement, mfa_requirement};
use lldap_domain::types::UserId;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};
use tracing::warn;

/// A proof stamped up to this many seconds ahead of the judging clock still opens its window.
pub const OPENING_ALLOWANCE: i64 = 60;
pub const KEPT_MARGIN: i64 = 3600;
pub const REREAD_EVERY: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofSettings {
    /// Seconds a proof opens Kerberos for.
    pub window: i64,
    pub same_address: bool,
    /// Seconds a window is kept past its end: the longest renewable life and a margin.
    pub kept: i64,
}

impl ProofSettings {
    pub fn new(window: u64, same_address: bool, longest_life: u64) -> Self {
        let seconds = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
        Self {
            window: seconds(window),
            same_address,
            kept: seconds(longest_life).saturating_add(KEPT_MARGIN),
        }
    }

    /// The address a window is kept under: the door's, and only with the tie on.
    pub fn peer_of(&self, peer: Option<IpAddr>) -> String {
        match (self.same_address, peer) {
            (true, Some(peer)) => peer.to_canonical().to_string(),
            _ => String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofWindow {
    pub opened_at: i64,
    pub until_at: i64,
    pub peer: String,
}

impl ProofWindow {
    pub fn covers(&self, at: i64) -> bool {
        self.opened_at - OPENING_ALLOWANCE <= at && at <= self.until_at
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofVerdict {
    NotAsked,
    Admitted,
    NoFreshProof,
}

/// The doors' own test: `always`, enrolled or not, or `enabled` and enrolled; never exempt.
pub fn proof_required(policy: MfaPolicy, facts: &UserFacts) -> bool {
    let status = MfaEnrollmentStatus {
        enrolled: facts.enrolled,
        exempt: facts.exempt,
    };
    mfa_requirement(policy, Some(&status)) != MfaRequirement::None
}

/// From memory alone; a user whose value or facts are not known is not required.
pub fn known_required(cache: &PolicyCache, entries: &Entries, user: &UserId) -> bool {
    let policy = cached_mfa_policy(cache, entries, user);
    let required = |(policy, facts): (MfaPolicy, &UserFacts)| proof_required(policy, facts);
    policy.zip(entries.facts_of(user)).is_some_and(required)
}

/// Kerberos is on and some resolved value can ask a factor.
pub fn proofs_live(cache: &PolicyCache) -> bool {
    cache.proofs().is_some() && mfa_can_be_on(cache.mfa_policy(), cache)
}

fn judge(
    cache: &PolicyCache,
    user: &UserId,
    admits: impl Fn(&ProofSettings, &ProofWindow) -> bool,
) -> ProofVerdict {
    let Some(settings) = cache.proofs().filter(|_| proofs_live(cache)) else {
        return ProofVerdict::NotAsked;
    };
    let entries = cache.get();
    if !known_required(cache, &entries, user) {
        return ProofVerdict::NotAsked;
    }
    match entries
        .windows_of(user)
        .iter()
        .any(|w| admits(&settings, w))
    {
        true => ProofVerdict::Admitted,
        false => ProofVerdict::NoFreshProof,
    }
}

/// At AS: a window covering `now`, made from the request's address when the tie is on.
pub fn proof_at_as(
    cache: &PolicyCache,
    user: &UserId,
    now: i64,
    peer: Option<IpAddr>,
) -> ProofVerdict {
    judge(cache, user, |settings, window| {
        let from = settings.peer_of(peer);
        let placed = !settings.same_address || (!from.is_empty() && window.peer == from);
        window.covers(now) && placed
    })
}

/// At TGS: the presented ticket's authentication time inside a window.
pub fn proof_at_tgs(cache: &PolicyCache, user: &UserId, authtime: i64) -> ProofVerdict {
    judge(cache, user, |_, window| window.covers(authtime))
}

/// The KDC's verdict: a refusal asks for the whole user again.
pub fn kdc_verdict(
    cache: &'static PolicyCache,
    user: &UserId,
    verdict: ProofVerdict,
) -> ProofVerdict {
    if verdict == ProofVerdict::NoFreshProof {
        cache.reread_soon(user);
    }
    verdict
}

pub trait ProofStore: UserBackendHandler + PolicyBackendHandler {}

impl<T: UserBackendHandler + PolicyBackendHandler + ?Sized> ProofStore for T {}

#[derive(Clone)]
pub(crate) struct WindowReader {
    store: Arc<dyn ProofStore>,
    runtime: tokio::runtime::Handle,
}

#[derive(Default)]
pub(crate) struct Reread {
    at: Option<Instant>,
    running: bool,
}

struct Rereading<'a> {
    cache: &'a PolicyCache,
    user: &'a UserId,
}

impl Drop for Rereading<'_> {
    fn drop(&mut self) {
        if let Some(reread) = self.cache.rereads().get_mut(self.user) {
            reread.running = false;
        }
    }
}

impl PolicyCache {
    pub fn proofs(&self) -> Option<ProofSettings> {
        *self.proofs.read().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn set_proofs(&self, proofs: Option<ProofSettings>) {
        *self.proofs.write().unwrap_or_else(PoisonError::into_inner) = proofs;
    }

    /// Under the writers' lock; while it is held the user is marked for its taker.
    pub fn put_window(&self, user: &UserId, window: ProofWindow) {
        let Ok(_writers) = self.writers.try_lock() else {
            self.mark(user);
            return;
        };
        self.edit(|entries| {
            let mut windows = entries.windows_of(user).to_vec();
            windows.push(window);
            entries.windows.insert(user.clone(), windows.into());
        });
    }

    /// Only under the writers' lock, as `take_marks` holds it.
    fn put_windows(&self, user: &UserId, windows: Vec<ProofWindow>) {
        self.edit(|entries| {
            entries.windows.insert(user.clone(), windows.into());
        });
    }

    pub fn serve_windows(&self, store: Arc<dyn ProofStore>, runtime: tokio::runtime::Handle) {
        let reader = WindowReader { store, runtime };
        *self.reader.write().unwrap_or_else(PoisonError::into_inner) = Some(reader);
    }

    fn rereads(&self) -> std::sync::MutexGuard<'_, HashMap<UserId, Reread>> {
        self.rereads.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One read in flight per user, and at most one a second.
    fn reread_due(&self, user: &UserId, now: Instant) -> bool {
        let mut rereads = self.rereads();
        let reread = rereads.entry(user.clone()).or_default();
        let recent = reread
            .at
            .is_some_and(|at| now.duration_since(at) < REREAD_EVERY);
        if recent || reread.running {
            return false;
        }
        reread.at = Some(now);
        reread.running = true;
        true
    }

    /// From the KDC's thread: the read runs on the server's runtime, for the next request.
    pub fn reread_soon(&'static self, user: &UserId) {
        let reader = self
            .reader
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let due = |_: &WindowReader| self.reread_due(user, Instant::now());
        let Some(WindowReader { store, runtime }) = reader.filter(due) else {
            return;
        };
        let user = user.clone();
        runtime.spawn(async move {
            let _rereading = Rereading {
                cache: self,
                user: &user,
            };
            user_written(&*store, self, &user).await;
        });
    }
}

/// One read for the required users; a failed one leaves them none, so they alone are refused.
pub(crate) async fn fill_windows<H>(handler: &H, cache: &PolicyCache, entries: &mut Entries)
where
    H: PolicyBackendHandler + ?Sized,
{
    if !proofs_live(cache) {
        return;
    }
    let held: &Entries = entries;
    let required = held
        .facts
        .keys()
        .filter(|user| known_required(cache, held, user));
    let mut windows: HashMap<UserId, Vec<ProofWindow>> =
        required.map(|user| (user.clone(), Vec::new())).collect();
    if windows.is_empty() {
        return;
    }
    let rows = match handler.read_proof_windows(None).await {
        Ok(rows) => rows,
        Err(e) => {
            warn!("The second factor's windows were not read: {e}");
            cache.note_read_failed();
            return;
        }
    };
    for (user, window) in rows {
        if let Some(held) = windows.get_mut(&user) {
            held.push(window);
        }
    }
    let windows = windows
        .into_iter()
        .map(|(user, kept)| (user, Arc::<[ProofWindow]>::from(kept)));
    entries.windows = windows.collect();
}

/// One user's windows again, as a write or a refusal asks; false when the read failed.
pub(crate) async fn take_user_windows<H>(handler: &H, cache: &PolicyCache, user: &UserId) -> bool
where
    H: PolicyBackendHandler + ?Sized,
{
    if !proofs_live(cache) {
        return true;
    }
    let entries = cache.get();
    if !known_required(cache, &entries, user) {
        if !entries.windows_of(user).is_empty() {
            cache.put_windows(user, Vec::new());
        }
        return true;
    }
    match handler.read_proof_windows(Some(user)).await {
        Ok(rows) => {
            cache.put_windows(user, rows.into_iter().map(|(_, w)| w).collect());
            true
        }
        Err(e) => {
            warn!("The second factor's windows of {user} were not read: {e}");
            cache.put_windows(user, Vec::new());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::{EffectiveItem, ItemSource, PolicyId, PolicyScope};
    use lldap_domain::types::Uuid;
    use pretty_assertions::assert_eq;

    const NOW: i64 = 1_700_000_000;
    const PEER: &str = "192.0.2.7";

    fn facts(name: &str, enrolled: bool, exempt: bool) -> UserFacts {
        UserFacts {
            uuid: Uuid::from_name_and_date(name, &chrono::NaiveDateTime::default()),
            enrolled,
            exempt,
        }
    }

    fn window(opened_at: i64, until_at: i64, peer: &str) -> ProofWindow {
        let peer = peer.to_owned();
        ProofWindow {
            opened_at,
            until_at,
            peer,
        }
    }

    fn settings(same_address: bool) -> ProofSettings {
        ProofSettings::new(600, same_address, 7 * 86_400)
    }

    fn unsourced(value: &str) -> EffectiveItem {
        EffectiveItem {
            key: crate::mfa::ENABLE_MFA.to_owned(),
            scope: PolicyScope::User,
            value: value.to_owned(),
            enforced: true,
            source: None,
        }
    }

    fn item(value: &str) -> Arc<[EffectiveItem]> {
        let source = ItemSource {
            policy_id: PolicyId(1),
            policy_name: "p".to_owned(),
            ou_key: "people".to_owned(),
        };
        let item = EffectiveItem {
            source: Some(source),
            ..unsourced(value)
        };
        vec![item].into()
    }

    fn cache_with(
        server: Option<MfaPolicy>,
        value: &str,
        user: &UserFacts,
        windows: &[ProofWindow],
    ) -> PolicyCache {
        let cache = PolicyCache::new();
        cache.set_proofs(Some(settings(false)));
        cache.set_mfa_policy(server);
        cache.set_mfa_item_live(true);
        let name = UserId::new("e2kuser");
        let mut entries = Entries::default();
        entries
            .ous_of_users
            .insert(name.clone(), "people".to_owned());
        entries
            .items_of_ous
            .insert("people".to_owned(), item(value));
        entries.facts.insert(name.clone(), user.clone());
        entries.windows.insert(name, windows.to_vec().into());
        cache.replace(entries);
        cache
    }

    #[test]
    fn test_a_window_covers_from_a_minute_before_its_opening_to_its_end_and_no_later() {
        let open = window(NOW, NOW + 600, "");
        let rows = [
            (NOW - 61, false),
            (NOW - 60, true),
            (NOW, true),
            (NOW + 600, true),
            (NOW + 601, false),
        ];
        for (at, covered) in rows {
            assert_eq!(open.covers(at), covered, "{}", at - NOW);
        }
        let kept = settings(false);
        assert_eq!(
            (kept.window, kept.kept, kept.peer_of(PEER.parse().ok())),
            (600, 7 * 86_400 + 3600, String::new()),
            "the window, the longest renewable life and an hour, and no address without the tie"
        );
        let tied = settings(true);
        assert_eq!(
            (tied.peer_of(PEER.parse().ok()), tied.peer_of(None)),
            (PEER.to_owned(), String::new())
        );
    }

    #[test]
    fn test_who_needs_a_proof_is_the_doors_own_test() {
        use MfaPolicy::*;
        let rows = [
            (Disabled, false, false, false),
            (Disabled, true, false, false),
            (Enrolled, false, false, false),
            (Enrolled, true, false, true),
            (Enrolled, true, true, false),
            (Always, false, false, true),
            (Always, true, false, true),
            (Always, false, true, false),
        ];
        for (policy, enrolled, exempt, required) in rows {
            let user = facts("e2kwho", enrolled, exempt);
            let label = format!("{policy:?}, enrolled {enrolled}, exempt {exempt}");
            assert_eq!(proof_required(policy, &user), required, "{label}");
        }
    }

    #[test]
    fn test_the_kdcs_question_from_memory() {
        use ProofVerdict::*;
        let user = UserId::new("e2kuser");
        let fresh = [window(NOW - 100, NOW + 500, "")];
        let past = [window(NOW - 1000, NOW - 400, "")];
        let (enrolled, bare) = (
            facts("e2kuser", true, false),
            facts("e2kuser", false, false),
        );
        let exempt = facts("e2kuser", true, true);
        type Row<'a> = (
            &'a str,
            Option<MfaPolicy>,
            &'a str,
            &'a UserFacts,
            &'a [ProofWindow],
            ProofVerdict,
        );
        let rows: [Row; 9] = [
            (
                "enabled, enrolled, no window",
                None,
                "enabled",
                &enrolled,
                &[],
                NoFreshProof,
            ),
            (
                "enabled, enrolled, a fresh window",
                None,
                "enabled",
                &enrolled,
                &fresh,
                Admitted,
            ),
            (
                "enabled, enrolled, after the window",
                None,
                "enabled",
                &enrolled,
                &past,
                NoFreshProof,
            ),
            (
                "enabled, not enrolled",
                None,
                "enabled",
                &bare,
                &[],
                NotAsked,
            ),
            ("off", None, "off", &enrolled, &[], NotAsked),
            ("exempt", None, "always", &exempt, &[], NotAsked),
            (
                "always, not enrolled",
                None,
                "always",
                &bare,
                &[],
                NoFreshProof,
            ),
            (
                "an explicit enabled over the OU's off",
                Some(MfaPolicy::Enrolled),
                "off",
                &enrolled,
                &[],
                NoFreshProof,
            ),
            (
                "an explicit off over the OU's always",
                Some(MfaPolicy::Disabled),
                "always",
                &enrolled,
                &[],
                NotAsked,
            ),
        ];
        for (label, server, value, facts, windows, verdict) in rows {
            let cache = cache_with(server, value, facts, windows);
            assert_eq!(proof_at_as(&cache, &user, NOW, None), verdict, "{label}");
        }
        let cache = cache_with(None, "always", &enrolled, &[]);
        let mut entries = (*cache.get()).clone();
        entries
            .items_of_ous
            .insert("people".to_owned(), vec![unsourced("always")].into());
        cache.replace(entries);
        assert_eq!(
            proof_at_as(&cache, &user, NOW, None),
            NotAsked,
            "an item without a source is the catalog's default and requires nothing"
        );
        let cache = cache_with(None, "always", &enrolled, &past);
        assert_eq!(
            (
                proof_at_as(&cache, &user, NOW, None),
                proof_at_tgs(&cache, &user, NOW - 700)
            ),
            (NoFreshProof, Admitted),
            "a ticket authenticated inside a window that has passed is still judged by that time"
        );
        assert_eq!(
            proof_at_tgs(&cache, &user, NOW - 1100),
            NoFreshProof,
            "before the window"
        );
    }

    #[test]
    fn test_the_address_tie_and_what_memory_does_not_know() {
        use ProofVerdict::*;
        let user = UserId::new("e2kuser");
        let enrolled = facts("e2kuser", true, false);
        let tied = [window(NOW, NOW + 600, PEER)];
        let cache = cache_with(None, "always", &enrolled, &tied);
        cache.set_proofs(Some(settings(true)));
        let other = "198.51.100.9".parse().ok();
        assert_eq!(
            [
                proof_at_as(&cache, &user, NOW, PEER.parse().ok()),
                proof_at_as(&cache, &user, NOW, other),
                proof_at_as(&cache, &user, NOW, None),
                proof_at_tgs(&cache, &user, NOW),
            ],
            [Admitted, NoFreshProof, NoFreshProof, Admitted],
            "with the tie on, AS asks the proof's address; TGS judges the time only"
        );
        let stranger = UserId::new("e2kstranger");
        cache.set_mfa_item_unknown();
        assert_eq!(
            [
                proof_at_as(&cache, &user, NOW, PEER.parse().ok()),
                proof_at_as(&cache, &stranger, NOW, None),
            ],
            [NotAsked, NotAsked],
            "the item not read: no user is known to need a proof, so today's kinit"
        );
        cache.set_mfa_policy(Some(MfaPolicy::Always));
        assert_eq!(
            [
                proof_at_as(&cache, &user, NOW, other),
                proof_at_as(&cache, &stranger, NOW, None),
            ],
            [NoFreshProof, NotAsked],
            "an explicit value with the item unread: the known user is judged, a user not in \
             memory is not"
        );
        let dual = "::ffff:192.0.2.7".parse().ok();
        cache.set_mfa_policy(None);
        cache.set_mfa_item_live(true);
        let mapped = window(NOW, NOW + 600, &settings(true).peer_of(dual));
        cache.put_windows(&user, vec![mapped]);
        assert_eq!(
            [
                proof_at_as(&cache, &user, NOW, PEER.parse().ok()),
                proof_at_as(&cache, &user, NOW, dual),
            ],
            [Admitted, Admitted],
            "a proof over a dual-stack listener (::ffff:192.0.2.7) admits a kinit from 192.0.2.7"
        );
        cache.set_proofs(None);
        assert_eq!(
            proof_at_as(&cache, &user, NOW, other),
            NotAsked,
            "Kerberos off"
        );
    }

    #[test]
    fn test_a_reread_runs_one_at_a_time_and_at_most_once_a_second() {
        let cache = PolicyCache::new();
        let (user, at) = (UserId::new("e2kreread"), Instant::now());
        let first = cache.reread_due(&user, at);
        let in_flight = cache.reread_due(&user, at + REREAD_EVERY * 2);
        drop(Rereading {
            cache: &cache,
            user: &user,
        });
        let soon = cache.reread_due(&user, at + REREAD_EVERY / 2);
        let later = cache.reread_due(&user, at + REREAD_EVERY);
        let other = cache.reread_due(&UserId::new("e2kother"), at);
        assert_eq!(
            [first, in_flight, soon, later, other],
            [true, false, false, true, true]
        );
    }
}
