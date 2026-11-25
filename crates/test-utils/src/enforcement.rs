use lldap_domain::types::UserId;
use lldap_domain_handlers::enforcement::{
    Attempt, Door, Entries, ItemCheck, ItemFlags, PolicyCache, UserState, ZONE_FILES,
    default_item_checks, load_zone_from, policy_cache, set_item_checks, set_test_clock,
};
use lldap_domain_handlers::instant::Timestamp;
use lldap_domain_handlers::policies::EffectiveItem;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenAttempt {
    pub user: UserId,
    pub door: Door,
    pub peer: Option<IpAddr>,
    pub now: Timestamp,
    pub second_factor: bool,
    pub value: String,
}

pub struct ScriptedCheck {
    key: &'static str,
    users: Vec<UserId>,
    allow: fn(&str) -> bool,
    reason: Option<&'static str>,
    real: Option<Arc<dyn ItemCheck>>,
    seen: Mutex<Vec<SeenAttempt>>,
}

impl ItemCheck for ScriptedCheck {
    fn key(&self) -> &'static str {
        self.key
    }

    fn also_enforces(&self) -> &'static [&'static str] {
        match &self.real {
            Some(real) => real.also_enforces(),
            None => &[],
        }
    }

    fn live(&self, cache: &PolicyCache) -> bool {
        self.real.as_ref().is_none_or(|real| real.live(cache))
    }

    fn judges(&self, user: &UserId) -> bool {
        self.users.contains(user)
    }

    fn may_refuse(&self, state: &UserState) -> bool {
        self.real.as_ref().is_none_or(|real| real.may_refuse(state))
    }

    fn reason(&self) -> Option<&'static str> {
        self.real.as_ref().map_or(self.reason, |real| real.reason())
    }

    fn judges_at_s4u(&self) -> bool {
        self.real.as_ref().is_none_or(|real| real.judges_at_s4u())
    }

    fn readable(&self, value: &str, state: &UserState) -> bool {
        self.real
            .as_ref()
            .is_none_or(|real| real.readable(value, state))
    }

    fn loaded(&self) -> bool {
        self.real.as_ref().is_none_or(|real| real.loaded())
    }

    fn allows(&self, attempt: &Attempt<'_>, value: &str, state: &UserState) -> bool {
        self.allows_among(attempt, value, &[], state)
    }

    fn allows_among(
        &self,
        attempt: &Attempt<'_>,
        value: &str,
        items: &[EffectiveItem],
        state: &UserState,
    ) -> bool {
        self.seen.lock().expect("seen").push(SeenAttempt {
            user: attempt.user.clone(),
            door: attempt.door,
            peer: attempt.peer,
            now: attempt.now,
            second_factor: attempt.second_factor,
            value: value.to_owned(),
        });
        match &self.real {
            Some(real) => real.allows_among(attempt, value, items, state),
            None => (self.allow)(value),
        }
    }
}

/// Installs one scripted check that judges only the test's own `users`, or none, with an
/// empty policy cache; the test must be `#[serial]`. Every other user is left alone, so tests
/// running beside it meet no check. The default checks and an empty cache come back on drop.
pub struct EnforcementGuard {
    check: Option<Arc<ScriptedCheck>>,
}

type Script<'a> = (
    &'a [&'a str],
    &'static str,
    fn(&str) -> bool,
    Option<&'static str>,
);

impl EnforcementGuard {
    pub fn none() -> Self {
        Self::install(None, None)
    }

    /// The real checks, with the cache, the flags and the clock put back on drop.
    pub fn default_checks() -> Self {
        let guard = Self::install(None, None);
        set_item_checks(default_item_checks());
        guard
    }

    pub fn allowing(users: &[&str], key: &'static str) -> Self {
        Self::install(Some((users, key, |_| true, None)), None)
    }

    pub fn refusing(users: &[&str], key: &'static str) -> Self {
        Self::install(Some((users, key, |_| false, None)), None)
    }

    /// Allows exactly the values `allow` accepts.
    pub fn deciding(users: &[&str], key: &'static str, allow: fn(&str) -> bool) -> Self {
        Self::install(Some((users, key, allow, None)), None)
    }

    /// As `deciding`, and a refusal gives `reason` after the key.
    pub fn deciding_with_reason(
        users: &[&str],
        key: &'static str,
        reason: &'static str,
        allow: fn(&str) -> bool,
    ) -> Self {
        Self::install(Some((users, key, allow, Some(reason))), None)
    }

    /// The real check, judging only `users`; its item's flag in the cache is the test's to set.
    pub fn judging(users: &[&str], real: Arc<dyn ItemCheck>) -> Self {
        Self::install(Some((users, real.key(), |_| true, None)), Some(real))
    }

    /// Every `Attempt::new` and `lock_clock()` read `now` until the guard drops.
    pub fn pin_clock(&self, now: Timestamp) {
        set_test_clock(Some(now));
    }

    fn install(script: Option<Script<'_>>, real: Option<Arc<dyn ItemCheck>>) -> Self {
        let check = script.map(|(users, key, allow, reason)| {
            Arc::new(ScriptedCheck {
                key,
                users: users.iter().map(|user| UserId::new(user)).collect(),
                allow,
                reason,
                real,
                seen: Mutex::default(),
            })
        });
        let checks: Vec<Arc<dyn ItemCheck>> = check
            .iter()
            .map(|check| Arc::clone(check) as Arc<dyn ItemCheck>)
            .collect();
        set_item_checks(checks.into());
        set_test_clock(None);
        hold_utc();
        policy_cache().replace(Entries::default());
        policy_cache().reset_door_reads();
        policy_cache().set_mfa_item_live(false);
        policy_cache().set_item_flags(ItemFlags::default());
        policy_cache().reset_activity_reads();
        Self { check }
    }

    pub fn seen(&self) -> Vec<SeenAttempt> {
        self.check
            .as_ref()
            .map(|check| check.seen.lock().expect("seen").clone())
            .unwrap_or_default()
    }

    pub fn take_seen(&self) -> Vec<SeenAttempt> {
        self.check
            .as_ref()
            .map(|check| std::mem::take(&mut *check.seen.lock().expect("seen")))
            .unwrap_or_default()
    }
}

fn hold_utc() {
    let utc = load_zone_from(Path::new(ZONE_FILES), "UTC").expect("UTC is built in");
    policy_cache().set_login_hours_zone(utc.zone);
}

impl Drop for EnforcementGuard {
    fn drop(&mut self) {
        set_item_checks(default_item_checks());
        set_test_clock(None);
        hold_utc();
        policy_cache().replace(Entries::default());
        policy_cache().reset_door_reads();
        policy_cache().set_mfa_item_live(false);
        policy_cache().set_item_flags(ItemFlags::default());
        policy_cache().reset_activity_reads();
    }
}
