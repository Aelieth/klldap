use chrono::{DateTime, Utc};
use lldap_domain::types::UserId;
use lldap_domain_handlers::enforcement::{
    Attempt, Door, Entries, ItemCheck, ItemFlags, UserState, default_item_checks, policy_cache,
    set_item_checks, set_test_clock,
};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenAttempt {
    pub user: UserId,
    pub door: Door,
    pub peer: Option<IpAddr>,
    pub now: DateTime<Utc>,
    pub second_factor: bool,
    pub value: String,
}

pub struct ScriptedCheck {
    key: &'static str,
    users: Vec<UserId>,
    allow: fn(&str) -> bool,
    reason: Option<&'static str>,
    seen: Mutex<Vec<SeenAttempt>>,
}

impl ItemCheck for ScriptedCheck {
    fn key(&self) -> &'static str {
        self.key
    }

    fn judges(&self, user: &UserId) -> bool {
        self.users.contains(user)
    }

    fn reason(&self) -> Option<&'static str> {
        self.reason
    }

    fn allows(&self, attempt: &Attempt<'_>, value: &str, _: &UserState) -> bool {
        self.seen.lock().expect("seen").push(SeenAttempt {
            user: attempt.user.clone(),
            door: attempt.door,
            peer: attempt.peer,
            now: attempt.now,
            second_factor: attempt.second_factor,
            value: value.to_owned(),
        });
        (self.allow)(value)
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
        Self::install(None)
    }

    pub fn allowing(users: &[&str], key: &'static str) -> Self {
        Self::install(Some((users, key, |_| true, None)))
    }

    pub fn refusing(users: &[&str], key: &'static str) -> Self {
        Self::install(Some((users, key, |_| false, None)))
    }

    /// Allows exactly the values `allow` accepts.
    pub fn deciding(users: &[&str], key: &'static str, allow: fn(&str) -> bool) -> Self {
        Self::install(Some((users, key, allow, None)))
    }

    /// As `deciding`, and a refusal gives `reason` after the key.
    pub fn deciding_with_reason(
        users: &[&str],
        key: &'static str,
        reason: &'static str,
        allow: fn(&str) -> bool,
    ) -> Self {
        Self::install(Some((users, key, allow, Some(reason))))
    }

    /// Every `Attempt::new` and `lock_clock()` read `now` until the guard drops.
    pub fn pin_clock(&self, now: DateTime<Utc>) {
        set_test_clock(Some(now));
    }

    fn install(script: Option<Script<'_>>) -> Self {
        let check = script.map(|(users, key, allow, reason)| {
            Arc::new(ScriptedCheck {
                key,
                users: users.iter().map(|user| UserId::new(user)).collect(),
                allow,
                reason,
                seen: Mutex::default(),
            })
        });
        let checks: Vec<Arc<dyn ItemCheck>> = check
            .iter()
            .map(|check| Arc::clone(check) as Arc<dyn ItemCheck>)
            .collect();
        set_item_checks(checks.into());
        set_test_clock(None);
        policy_cache().replace(Entries::default());
        policy_cache().set_mfa_item_live(false);
        policy_cache().set_item_flags(ItemFlags::default());
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

impl Drop for EnforcementGuard {
    fn drop(&mut self) {
        set_item_checks(default_item_checks());
        set_test_clock(None);
        policy_cache().replace(Entries::default());
        policy_cache().set_mfa_item_live(false);
        policy_cache().set_item_flags(ItemFlags::default());
    }
}
