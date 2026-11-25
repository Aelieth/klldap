use crate::enforcement::{Attempt, ItemCheck, LOGIN_HOURS, PolicyCache, UNREADABLE, UserState};
use crate::policies::{Policy, PolicyId};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use std::sync::{Mutex, PoisonError};

pub const OUTSIDE: &str = "outside login hours";
const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const DAY_ENDS: u16 = 24 * 60;

/// Minutes of the day, `[start, end)`, on the days whose bits are set, Monday the lowest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    days: u8,
    start: u16,
    end: u16,
}

/// No window: always.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginHours(Vec<Window>);

pub fn parse(value: &str) -> Result<LoginHours, String> {
    if value.is_empty() {
        return Ok(LoginHours::default());
    }
    let windows = value.split(';').map(entry).collect::<Result<_, _>>();
    windows.map(LoginHours)
}

fn entry(part: &str) -> Result<Window, String> {
    let part = part.trim();
    if part.is_empty() {
        return Err("login-hours entries cannot be empty".to_owned());
    }
    let Some((days, times)) = part.rsplit_once(' ') else {
        return Err("login-hours entries must be DAY[-DAY] HH:MM-HH:MM".to_owned());
    };
    let named = days.split('-').map(day).collect::<Result<Vec<_>, _>>()?;
    let days = match *named.as_slice() {
        [one] => span(one, one),
        [first, last] => span(first, last),
        _ => return Err("day range must be DAY or DAY-DAY".to_owned()),
    };
    let Some((start, end)) = times.split_once('-') else {
        return Err("time range must be HH:MM-HH:MM".to_owned());
    };
    let (start, end) = (minutes(start)?, minutes(end)?);
    if start >= end {
        return Err("time range start must be before end".to_owned());
    }
    Ok(Window { days, start, end })
}

fn day(name: &str) -> Result<usize, String> {
    let known = DAYS.iter().position(|day| day.eq_ignore_ascii_case(name));
    known.ok_or_else(|| format!("unknown day '{name}'"))
}

fn span(first: usize, last: usize) -> u8 {
    let days = |from: usize, to: usize| (from..=to).fold(0_u8, |set, day| set | (1_u8 << day));
    if first <= last {
        days(first, last)
    } else {
        days(first, 6) | days(0, last)
    }
}

fn minutes(value: &str) -> Result<u16, String> {
    let (hour, minute) = value
        .split_once(':')
        .ok_or_else(|| "time must be HH:MM".to_owned())?;
    if hour.len() != 2 || minute.len() != 2 {
        return Err("time must be HH:MM".to_owned());
    }
    let number = |text: &str, invalid: &str| {
        let digits = text.bytes().all(|b| b.is_ascii_digit());
        let parsed = text.parse::<u16>().ok().filter(|_| digits);
        parsed.ok_or_else(|| invalid.to_owned())
    };
    let hour = number(hour, "invalid hour")?;
    let minute = number(minute, "invalid minute")?;
    match (hour, minute) {
        (24, 0) => Ok(DAY_ENDS),
        (0..=23, 0..=59) => Ok(hour * 60 + minute),
        _ => Err("hour must be 00-23 and minute 00-59, or 24:00 as an end".to_owned()),
    }
}

/// The instant on the zone's wall clock: its weekday, and its second of the day.
pub fn judge(hours: &LoginHours, zone: &TimeZone, at: Timestamp) -> bool {
    if hours.0.is_empty() {
        return true;
    }
    let wall = zone.to_datetime(at);
    let day = 1_u8 << wall.weekday().to_monday_zero_offset();
    let clock = [wall.hour(), wall.minute(), wall.second()].map(i32::from);
    let now = clock[0] * 3600 + clock[1] * 60 + clock[2];
    let second = |minutes: u16| i32::from(minutes) * 60;
    let within = |window: &Window| second(window.start) <= now && now < second(window.end);
    hours
        .0
        .iter()
        .any(|window| window.days & day != 0 && within(window))
}

pub struct LoginHoursCheck {
    cache: &'static PolicyCache,
}

impl LoginHoursCheck {
    /// Judged in the zone this cache holds.
    pub fn on(cache: &'static PolicyCache) -> Self {
        Self { cache }
    }
}

impl ItemCheck for LoginHoursCheck {
    fn key(&self) -> &'static str {
        LOGIN_HOURS
    }

    fn live(&self, cache: &PolicyCache) -> bool {
        !cache.item_off(LOGIN_HOURS)
    }

    fn reason(&self) -> Option<&'static str> {
        Some(OUTSIDE)
    }

    fn judges_at_s4u(&self) -> bool {
        false
    }

    fn readable(&self, value: &str, _: &UserState) -> bool {
        self.loaded() && parse(value).is_ok()
    }

    fn loaded(&self) -> bool {
        self.cache.login_hours_zone().is_some()
    }

    fn allows(&self, attempt: &Attempt<'_>, value: &str, _: &UserState) -> bool {
        let zone = self.cache.login_hours_zone();
        let (Some(zone), Ok(hours)) = (zone, parse(value)) else {
            return false;
        };
        judge(&hours, &zone, attempt.now)
    }
}

/// One warning per linked value that does not parse, said again only once the value changes.
#[derive(Default)]
pub struct UnparsedWarning(Mutex<Vec<(PolicyId, String)>>);

pub static UNPARSED: UnparsedWarning = UnparsedWarning::new();

impl UnparsedWarning {
    pub const fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    pub fn take(&self, policies: &[Policy]) -> Vec<String> {
        let mut warned = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut broken, mut said) = (Vec::new(), Vec::new());
        for policy in policies
            .iter()
            .filter(|policy| !policy.linked_ous.is_empty())
        {
            let Some(value) = policy.items.get(LOGIN_HOURS) else {
                continue;
            };
            let Err(cause) = parse(value) else {
                continue;
            };
            let held = (policy.id, value.clone());
            if !warned.contains(&held) {
                said.push(format!(
                    "The policy \"{}\" sets {LOGIN_HOURS} to a value that does not parse \
                     ({cause}); the users it applies to are refused (policy: {UNREADABLE})",
                    policy.name
                ));
            }
            broken.push(held);
        }
        *warned = broken;
        said
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::{
        Door, Entries, ItemFlags, NOT_LOADED, Refusal, admit_at_kdc_with, decide,
        default_item_checks, live_checks, policy_cache,
    };
    use crate::lockout::{DURATION, LockRow, Lockout, THRESHOLD};
    use crate::policies::{
        AttachedPolicy, EffectiveItem, POLICY_ITEM_CATALOG, PolicyLevel, PolicyScope,
        resolve_effective_items, validate_login_hours,
    };
    use lldap_domain::types::UserId;
    use pretty_assertions::assert_eq;
    use std::collections::{BTreeMap, HashMap};
    use std::path::Path;
    use std::sync::Arc;

    const MON: u8 = 1;
    const TUE: u8 = 2;
    const WED: u8 = 4;
    const THU: u8 = 8;
    const FRI: u8 = 16;
    const SAT: u8 = 32;
    const SUN: u8 = 64;
    const WEEK: u8 = 127;

    fn window(days: u8, start: u16, end: u16) -> Window {
        Window { days, start, end }
    }

    fn instant(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn zone(name: &str) -> TimeZone {
        let data = std::fs::read(Path::new("/usr/share/zoneinfo").join(name)).unwrap();
        TimeZone::tzif(name, &data).unwrap()
    }

    fn judged(value: &str, zone: &TimeZone, rows: &[(&str, bool)]) {
        let hours = parse(value).unwrap();
        let got: Vec<_> = rows
            .iter()
            .map(|(at, _)| (*at, judge(&hours, zone, instant(at))))
            .collect();
        assert_eq!(got, rows.to_vec(), "{value}");
    }

    fn cache_in(zone: TimeZone) -> &'static PolicyCache {
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        cache.set_login_hours_zone(zone);
        cache
    }

    fn hours_item(value: &str) -> EffectiveItem {
        EffectiveItem {
            key: LOGIN_HOURS.to_owned(),
            scope: PolicyScope::User,
            value: value.to_owned(),
            enforced: true,
            source: None,
        }
    }

    fn attempt<'a>(user: &'a UserId, door: Door, at: &str) -> Attempt<'a> {
        Attempt {
            user,
            door,
            peer: None,
            now: instant(at),
            second_factor: false,
        }
    }

    fn refused(
        item: &'static str,
        door: Door,
        reason: Option<&'static str>,
    ) -> Result<(), Refusal> {
        Err(Refusal { item, door, reason })
    }

    #[test]
    fn test_the_parser_takes_exactly_the_validators_grammar_and_24_00_as_an_end_only() {
        let hours = |windows: Vec<Window>| Ok(LoginHours(windows));
        let refusal = |text: &str| Err(text.to_owned());
        let hour_text = "hour must be 00-23 and minute 00-59, or 24:00 as an end";
        let rows: Vec<(&str, Result<LoginHours, String>)> = vec![
            ("", hours(vec![])),
            ("mon 08:00-18:00", hours(vec![window(MON, 480, 1080)])),
            (
                "mon-fri 08:00-18:00",
                hours(vec![window(MON | TUE | WED | THU | FRI, 480, 1080)]),
            ),
            (
                "fri-mon 08:00-18:00",
                hours(vec![window(FRI | SAT | SUN | MON, 480, 1080)]),
            ),
            ("mon-mon 08:00-18:00", hours(vec![window(MON, 480, 1080)])),
            ("tue-mon 08:00-18:00", hours(vec![window(WEEK, 480, 1080)])),
            ("sun-sat 00:00-24:00", hours(vec![window(WEEK, 0, 1440)])),
            (
                "MON-Fri 08:00-18:00",
                hours(vec![window(MON | TUE | WED | THU | FRI, 480, 1080)]),
            ),
            (
                "mon-fri 08:00-18:00;sat 09:00-12:00",
                hours(vec![
                    window(MON | TUE | WED | THU | FRI, 480, 1080),
                    window(SAT, 540, 720),
                ]),
            ),
            (
                " mon 08:00-12:00 ; tue 13:00-17:00 ",
                hours(vec![window(MON, 480, 720), window(TUE, 780, 1020)]),
            ),
            ("mon +8:00-09:00", refusal("invalid hour")),
            ("mon 08:+5-09:00", refusal("invalid minute")),
            ("mon 23:00-24:00", hours(vec![window(MON, 1380, 1440)])),
            (
                "mon 24:00-24:00",
                refusal("time range start must be before end"),
            ),
            (
                "mon 24:00-23:00",
                refusal("time range start must be before end"),
            ),
            ("mon 08:00-24:01", refusal(hour_text)),
            ("mon 08:60-09:00", refusal(hour_text)),
            ("mon 25:00-26:00", refusal(hour_text)),
            ("mon  08:00-18:00", refusal("unknown day 'mon '")),
            ("mon 08:00 - 18:00", refusal("unknown day 'mon 08:00 '")),
            ("mon - fri 08:00-18:00", refusal("unknown day 'mon '")),
            (
                "mon\t08:00-18:00",
                refusal("login-hours entries must be DAY[-DAY] HH:MM-HH:MM"),
            ),
            (
                "mon 08:00-18:00;",
                refusal("login-hours entries cannot be empty"),
            ),
            ("  ", refusal("login-hours entries cannot be empty")),
            ("funday 08:00-09:00", refusal("unknown day 'funday'")),
            ("mon 8:00-09:00", refusal("time must be HH:MM")),
            ("mon 0800-1800", refusal("time must be HH:MM")),
            ("mon 08:00-18:00-19:00", refusal("time must be HH:MM")),
            ("mon 08:00", refusal("time range must be HH:MM-HH:MM")),
            ("mon xx:00-09:00", refusal("invalid hour")),
            ("mon 08:xx-09:00", refusal("invalid minute")),
            (
                "mon 18:00-08:00",
                refusal("time range start must be before end"),
            ),
            (
                "mon-tue-wed 08:00-18:00",
                refusal("day range must be DAY or DAY-DAY"),
            ),
        ];
        for (value, expected) in rows {
            assert_eq!(parse(value), expected, "{value:?}");
            assert_eq!(
                validate_login_hours(value),
                expected.map(drop),
                "{value:?}: the validator answers as the parser"
            );
        }
    }

    #[test]
    fn test_in_utc_a_window_is_half_open_at_the_second_on_its_weekdays() {
        let utc = TimeZone::UTC;
        judged(
            "mon 08:00-18:00",
            &utc,
            &[
                ("2026-11-16T07:59:59Z", false),
                ("2026-11-16T08:00:00Z", true),
                ("2026-11-16T17:59:59Z", true),
                ("2026-11-16T17:59:59.999Z", true),
                ("2026-11-16T18:00:00Z", false),
                ("2026-11-17T12:00:00Z", false),
            ],
        );
        judged(
            "fri-mon 08:00-18:00",
            &utc,
            &[
                ("2026-11-19T12:00:00Z", false),
                ("2026-11-20T12:00:00Z", true),
                ("2026-11-21T12:00:00Z", true),
                ("2026-11-22T12:00:00Z", true),
                ("2026-11-23T12:00:00Z", true),
                ("2026-11-24T12:00:00Z", false),
            ],
        );
        judged(
            "mon 23:00-24:00",
            &utc,
            &[
                ("2026-11-16T22:59:59Z", false),
                ("2026-11-16T23:59:59Z", true),
                ("2026-11-17T00:00:00Z", false),
            ],
        );
        judged(
            "mon-mon 08:00-18:00",
            &utc,
            &[
                ("2026-11-16T12:00:00Z", true),
                ("2026-11-17T12:00:00Z", false),
            ],
        );
        judged(
            "tue-mon 08:00-18:00",
            &utc,
            &[("2026-11-21T12:00:00Z", true)],
        );
        judged(
            "",
            &utc,
            &[
                ("2026-11-17T03:00:00Z", true),
                ("2026-11-21T23:59:59Z", true),
            ],
        );
    }

    #[test]
    fn test_in_chicago_on_2026_03_08_only_the_wall_clock_minutes_that_happen_admit() {
        let chicago = zone("America/Chicago");
        judged(
            "sun 02:00-03:00",
            &chicago,
            &[
                ("2026-03-08T07:59:59Z", false),
                ("2026-03-08T08:00:00Z", false),
            ],
        );
        judged(
            "sun 02:30-03:30",
            &chicago,
            &[
                ("2026-03-08T08:00:00Z", true),
                ("2026-03-08T08:29:59Z", true),
                ("2026-03-08T08:30:00Z", false),
            ],
        );
        judged(
            "sun 01:30-02:30",
            &chicago,
            &[
                ("2026-03-08T07:59:59Z", true),
                ("2026-03-08T08:00:00Z", false),
            ],
        );
    }

    #[test]
    fn test_in_chicago_on_2026_11_01_the_repeated_hour_admits_during_both_passes() {
        let chicago = zone("America/Chicago");
        judged(
            "sun 01:00-02:00",
            &chicago,
            &[
                ("2026-11-01T05:59:59Z", false),
                ("2026-11-01T06:00:00Z", true),
                ("2026-11-01T06:59:59Z", true),
                ("2026-11-01T07:00:00Z", true),
                ("2026-11-01T07:59:59Z", true),
                ("2026-11-01T08:00:00Z", false),
            ],
        );
        judged(
            "sun 01:30-02:30",
            &chicago,
            &[
                ("2026-11-01T06:29:59Z", false),
                ("2026-11-01T06:30:00Z", true),
                ("2026-11-01T06:59:59Z", true),
                ("2026-11-01T07:00:00Z", false),
                ("2026-11-01T07:30:00Z", true),
                ("2026-11-01T08:29:59Z", true),
                ("2026-11-01T08:30:00Z", false),
            ],
        );
    }

    #[test]
    fn test_in_santiago_the_change_at_midnight_moves_saturdays_last_hour_and_sundays_first() {
        let santiago = zone("America/Santiago");
        judged(
            "sat 23:00-24:00",
            &santiago,
            &[
                ("2026-04-05T01:59:59Z", false),
                ("2026-04-05T02:00:00Z", true),
                ("2026-04-05T02:59:59Z", true),
                ("2026-04-05T03:00:00Z", true),
                ("2026-04-05T03:59:59Z", true),
                ("2026-04-05T04:00:00Z", false),
            ],
        );
        judged(
            "sat 23:30-24:00",
            &santiago,
            &[
                ("2026-04-05T02:29:59Z", false),
                ("2026-04-05T02:30:00Z", true),
                ("2026-04-05T02:59:59Z", true),
                ("2026-04-05T03:00:00Z", false),
                ("2026-04-05T03:29:59Z", false),
                ("2026-04-05T03:30:00Z", true),
                ("2026-04-05T03:59:59Z", true),
                ("2026-04-05T04:00:00Z", false),
            ],
        );
        judged(
            "sun 00:00-04:00",
            &santiago,
            &[("2026-04-05T04:00:00Z", true)],
        );
        judged(
            "sun 00:00-01:00",
            &santiago,
            &[
                ("2026-09-06T03:59:59Z", false),
                ("2026-09-06T04:00:00Z", false),
            ],
        );
        judged(
            "sun 00:00-01:30",
            &santiago,
            &[
                ("2026-09-06T04:00:00Z", true),
                ("2026-09-06T04:29:59Z", true),
            ],
        );
        judged(
            "sat 23:00-24:00",
            &santiago,
            &[
                ("2026-09-06T03:59:59Z", true),
                ("2026-09-06T04:00:00Z", false),
            ],
        );
    }

    #[test]
    fn test_the_check_refuses_outside_its_windows_with_its_reason_and_never_at_s4u() {
        let check: Arc<dyn ItemCheck> = Arc::new(LoginHoursCheck::on(cache_in(TimeZone::UTC)));
        let checks = vec![check.clone()];
        let items = [hours_item("mon 08:00-18:00")];
        let bob = UserId::new("h2bob");
        let outside = |door| refused(LOGIN_HOURS, door, Some(OUTSIDE));
        let doors = [
            Door::LdapBind,
            Door::SimpleLogin,
            Door::WebLogin,
            Door::Refresh,
            Door::TokenUse,
            Door::KerberosAs,
            Door::KerberosTgs,
        ];
        for door in doors {
            let rows = [
                ("2026-11-16T07:59:59Z", outside(door)),
                ("2026-11-16T08:00:00Z", Ok(())),
                ("2026-11-16T17:59:59Z", Ok(())),
                ("2026-11-16T18:00:00Z", outside(door)),
            ];
            for (at, expected) in rows {
                let attempt = attempt(&bob, door, at);
                let got = decide(&attempt, &items, &UserState::default(), &checks);
                assert_eq!(got, expected, "{door:?} {at}");
            }
        }
        let late = attempt(&bob, Door::KerberosS4u, "2026-11-16T18:00:00Z");
        assert_eq!(
            decide(&late, &items, &UserState::default(), &checks),
            Ok(()),
            "an S4U request is not judged by the hours"
        );
        let refusal = Refusal {
            item: LOGIN_HOURS,
            door: Door::LdapBind,
            reason: Some(OUTSIDE),
        };
        assert_eq!(
            (
                check.key(),
                check.reason(),
                check.judges_at_s4u(),
                refusal.detail()
            ),
            (
                "login-hours",
                Some("outside login hours"),
                false,
                "policy: login-hours (outside login hours)".to_owned()
            )
        );
    }

    #[test]
    fn test_the_check_judges_the_second_an_instant_falls_in_also_before_1970() {
        let check = LoginHoursCheck::on(cache_in(TimeZone::UTC));
        let bob = UserId::new("g1bob");
        let rows = [
            ("mon 08:00-18:00", "2026-11-16T07:59:59.999999999Z", false),
            ("mon 08:00-18:00", "2026-11-16T17:59:59.999999999Z", true),
            ("wed 23:00-24:00", "1969-12-31T23:59:59.5Z", true),
            ("thu 00:00-01:00", "1969-12-31T23:59:59.5Z", false),
            ("tue 03:14-03:15", "2038-01-19T03:14:08Z", true),
        ];
        for (value, at, allowed) in rows {
            let attempt = attempt(&bob, Door::LdapBind, at);
            let got = check.allows(&attempt, value, &UserState::default());
            assert_eq!(got, allowed, "{value} at {at}");
        }
    }

    #[test]
    fn test_a_stored_value_that_does_not_parse_is_refused_as_unreadable() {
        let cache = cache_in(TimeZone::UTC);
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(LoginHoursCheck::on(cache))];
        let bad = [hours_item("funday 08:00-18:00")];
        let bob = UserId::new("h2bob");
        cache.replace(Entries {
            ous_of_users: HashMap::from([(bob.clone(), "people".to_owned())]),
            items_of_ous: HashMap::from([("people".to_owned(), bad.to_vec().into())]),
            ..Entries::default()
        });
        cache.set_item_flags(ItemFlags {
            login_hours: true,
            ..ItemFlags::default()
        });
        let counter = Lockout::default();
        let unreadable = |door| refused(UNREADABLE, door, None);
        for door in [Door::LdapBind, Door::WebLogin, Door::KerberosAs] {
            let attempt = attempt(&bob, door, "2026-11-16T12:00:00Z");
            let decided = decide(&attempt, &bad, &UserState::default(), &checks);
            let at_kdc = admit_at_kdc_with(cache, &counter, &attempt, &checks);
            assert_eq!(
                (decided, at_kdc),
                (unreadable(door), unreadable(door)),
                "{door:?}"
            );
        }
        let s4u = attempt(&bob, Door::KerberosS4u, "2026-11-16T12:00:00Z");
        assert_eq!(
            admit_at_kdc_with(cache, &counter, &s4u, &checks),
            Ok(()),
            "an S4U request is not judged by the hours, readable or not"
        );
        assert_eq!(
            Refusal {
                item: UNREADABLE,
                door: Door::LdapBind,
                reason: None
            }
            .detail(),
            "policy: unreadable"
        );
    }

    #[test]
    fn test_an_s4u_request_for_a_user_the_cache_lacks_reads_nothing_for_the_hours() {
        let cache = cache_in(TimeZone::UTC);
        cache.set_item_flags(ItemFlags {
            login_hours: true,
            ..ItemFlags::default()
        });
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(LoginHoursCheck::on(cache))];
        let (counter, absent) = (Lockout::default(), UserId::new("h2absent"));
        let judged = |door| {
            let reads = cache.reads();
            let attempt = attempt(&absent, door, "2026-11-16T18:00:00Z");
            let verdict = admit_at_kdc_with(cache, &counter, &attempt, &checks);
            (verdict, cache.reads() - reads)
        };
        assert_eq!(
            (judged(Door::KerberosS4u), judged(Door::KerberosAs)),
            (
                (Ok(()), 0),
                (refused(NOT_LOADED, Door::KerberosAs, None), 1)
            ),
            "the hours live, the user not in the cache: S4U reads nothing and admits; the AS \
             reads the cache and refuses"
        );
    }

    #[test]
    fn test_a_linked_value_that_does_not_parse_warns_once_naming_the_policy_and_the_item() {
        let policy = |value: &str, ous: &[&str]| Policy {
            id: PolicyId(7),
            name: "Night shift".to_owned(),
            description: String::new(),
            items: BTreeMap::from([(LOGIN_HOURS.to_owned(), value.to_owned())]),
            linked_ous: ous.iter().map(|ou| (*ou).to_owned()).collect(),
        };
        let said = |cause: &str| {
            vec![format!(
                "The policy \"Night shift\" sets login-hours to a value that does not parse \
                 ({cause}); the users it applies to are refused (policy: unreadable)"
            )]
        };
        let funday = "unknown day 'funday'";
        type Row<'a> = (&'a str, &'a str, &'a [&'a str], Vec<String>);
        let rows: [Row; 9] = [
            (
                "a value that parses",
                "mon 08:00-18:00",
                &["people"],
                vec![],
            ),
            (
                "it no longer parses",
                "funday 08:00-18:00",
                &["people"],
                said(funday),
            ),
            ("unchanged", "funday 08:00-18:00", &["people"], vec![]),
            ("unchanged again", "funday 08:00-18:00", &["people"], vec![]),
            (
                "another value that does not parse",
                "mon 8:00-18:00",
                &["people"],
                said("time must be HH:MM"),
            ),
            ("it parses again", "mon 08:00-18:00", &["people"], vec![]),
            (
                "it no longer parses, again",
                "funday 08:00-18:00",
                &["people"],
                said(funday),
            ),
            ("unlinked", "funday 08:00-18:00", &[], vec![]),
            ("linked again", "funday 08:00-18:00", &[""], said(funday)),
        ];
        let warning = UnparsedWarning::new();
        for (label, value, ous, expected) in rows {
            assert_eq!(warning.take(&[policy(value, ous)]), expected, "{label}");
        }
        let other = Policy {
            id: PolicyId(8),
            name: "Hours".to_owned(),
            ..policy("tue 25:00-26:00", &["labs"])
        };
        let both = warning.take(&[policy("funday 08:00-18:00", &[""]), other]);
        assert_eq!(
            both,
            vec![
                "The policy \"Hours\" sets login-hours to a value that does not parse (hour must \
                 be 00-23 and minute 00-59, or 24:00 as an end); the users it applies to are \
                 refused (policy: unreadable)"
                    .to_owned()
            ],
            "each policy is said once, by name"
        );
    }

    #[test]
    fn test_the_check_judges_in_the_zone_its_cache_holds() {
        let items = [hours_item("sun 01:00-02:00")];
        let bob = UserId::new("h2bob");
        let at = attempt(&bob, Door::LdapBind, "2026-11-01T07:30:00Z");
        let judged_in = |zone: TimeZone| {
            let check = LoginHoursCheck::on(cache_in(zone));
            check.allows(&at, &items[0].value, &UserState::default())
        };
        assert_eq!(
            (judged_in(zone("America/Chicago")), judged_in(TimeZone::UTC)),
            (true, false),
            "07:30Z is 01:30 in Chicago and 07:30 in UTC"
        );
    }

    #[test]
    fn test_until_the_start_sets_the_zone_a_live_check_is_unread_at_the_doors_and_the_kdc() {
        let cache: &'static PolicyCache = Box::leak(Box::new(PolicyCache::new()));
        let checks: Vec<Arc<dyn ItemCheck>> = vec![Arc::new(LoginHoursCheck::on(cache))];
        let items = [hours_item("mon 08:00-18:00")];
        let bob = UserId::new("h2bob");
        cache.replace(Entries {
            ous_of_users: HashMap::from([(bob.clone(), "people".to_owned())]),
            items_of_ous: HashMap::from([("people".to_owned(), items.to_vec().into())]),
            ..Entries::default()
        });
        let counter = Lockout::default();
        let (inside, outside) = ("2026-11-16T12:00:00Z", "2026-11-16T18:00:00Z");
        let kdc = |door, at| admit_at_kdc_with(cache, &counter, &attempt(&bob, door, at), &checks);
        let off = (
            kdc(Door::KerberosAs, outside),
            kdc(Door::KerberosS4u, outside),
        );
        cache.set_item_flags(ItemFlags {
            login_hours: true,
            ..ItemFlags::default()
        });
        let judged = || {
            let state = UserState::default();
            let door = attempt(&bob, Door::LdapBind, inside);
            (
                checks[0].readable(&items[0].value, &state),
                decide(&door, &items, &state, &checks),
                kdc(Door::KerberosAs, inside),
                kdc(Door::KerberosAs, outside),
                kdc(Door::KerberosS4u, outside),
            )
        };
        let unset = judged();
        cache.set_login_hours_zone(TimeZone::UTC);
        let set = judged();
        assert_eq!(off, (Ok(()), Ok(())), "the item off: no zone is needed");
        assert_eq!(
            (unset, set),
            (
                (
                    false,
                    refused(UNREADABLE, Door::LdapBind, None),
                    refused(NOT_LOADED, Door::KerberosAs, None),
                    refused(NOT_LOADED, Door::KerberosAs, None),
                    Ok(())
                ),
                (
                    true,
                    Ok(()),
                    Ok(()),
                    refused(LOGIN_HOURS, Door::KerberosAs, Some(OUTSIDE)),
                    Ok(())
                )
            ),
            "no zone yet: not readable, the doors refuse it unreadable and the KDC not loaded \
             yet; once the start sets it, judged in it"
        );
    }

    #[test]
    fn test_with_the_item_off_the_check_costs_nothing() {
        policy_cache().set_login_hours_zone(TimeZone::UTC);
        let cache = cache_in(TimeZone::UTC);
        let bob = UserId::new("h2bob");
        let items = [hours_item("mon 08:00-18:00")];
        cache.replace(Entries {
            ous_of_users: HashMap::from([(bob.clone(), "people".to_owned())]),
            items_of_ous: HashMap::from([("people".to_owned(), items.to_vec().into())]),
            ..Entries::default()
        });
        let (counter, checks) = (Lockout::default(), default_item_checks());
        let at = attempt(&bob, Door::KerberosAs, "2026-11-16T18:00:00Z");
        let judged = || {
            let live = live_checks(&checks, cache);
            let reads = cache.reads();
            let verdict = admit_at_kdc_with(cache, &counter, &at, &checks);
            let hours_live = live.iter().any(|check| check.key() == LOGIN_HOURS);
            (hours_live, verdict, cache.reads() - reads)
        };
        let off = judged();
        cache.set_item_flags(ItemFlags {
            login_hours: true,
            ..ItemFlags::default()
        });
        let on = judged();
        assert_eq!(
            (off, on),
            (
                (false, Ok(()), 0),
                (
                    true,
                    refused(LOGIN_HOURS, Door::KerberosAs, Some(OUTSIDE)),
                    1
                )
            ),
            "off: not live and no read; on: one read of the cache"
        );
    }

    #[test]
    fn test_an_ous_hours_reach_the_ous_below_it_until_one_blocks() {
        let level = |ou: &str, blocked: bool, value: Option<&str>| PolicyLevel {
            ou_key: ou.to_owned(),
            blocked,
            policy: value.map(|value| AttachedPolicy {
                id: PolicyId(1),
                name: format!("on {ou}"),
                items: BTreeMap::from([(LOGIN_HOURS.to_owned(), value.to_owned())]),
            }),
        };
        let day = Some("mon 08:00-18:00");
        let evening = Some("mon 18:00-20:00");
        let checks: Vec<Arc<dyn ItemCheck>> =
            vec![Arc::new(LoginHoursCheck::on(cache_in(TimeZone::UTC)))];
        let bob = UserId::new("h2bob");
        let at = attempt(&bob, Door::LdapBind, "2026-11-16T18:30:00Z");
        let outside = refused(LOGIN_HOURS, Door::LdapBind, Some(OUTSIDE));
        let rows = [
            (
                "set on the user's OU",
                vec![level("", false, None), level("people", false, day)],
                outside,
            ),
            (
                "inherited from the root",
                vec![
                    level("", false, day),
                    level("people", false, None),
                    level("people\\labs", false, None),
                ],
                outside,
            ),
            (
                "the closest OU wins",
                vec![level("", false, day), level("people", false, evening)],
                Ok(()),
            ),
            (
                "below a block",
                vec![level("", false, day), level("people", true, None)],
                Ok(()),
            ),
            (
                "the blocking OU's own policy",
                vec![level("", false, evening), level("people", true, day)],
                outside,
            ),
        ];
        for (label, levels, expected) in rows {
            let items = resolve_effective_items(POLICY_ITEM_CATALOG, &levels);
            let got = decide(&at, &items, &UserState::default(), &checks);
            assert_eq!(got, expected, "{label}");
        }
    }

    #[test]
    fn test_login_hours_is_judged_last_so_a_lock_is_named_before_it() {
        policy_cache().set_login_hours_zone(TimeZone::UTC);
        let checks = default_item_checks();
        let keys: Vec<&str> = checks.iter().map(|check| check.key()).collect();
        assert_eq!(
            (keys.first().copied(), keys.last().copied()),
            (Some(THRESHOLD), Some(LOGIN_HOURS)),
            "{keys:?}"
        );
        let bob = UserId::new("h2bob");
        let at = attempt(&bob, Door::LdapBind, "2026-11-16T18:00:00Z");
        let failed = instant("2026-11-16T17:59:00Z");
        let counter = Lockout::default();
        let row = LockRow {
            fail_count: 3,
            last_failed: Some(failed),
            ..LockRow::default()
        };
        counter.seed(&bob, row);
        let locked = counter.user_state(&bob);
        let mut items = vec![hours_item("mon 08:00-18:00")];
        for (key, value) in [(THRESHOLD, "3"), (DURATION, "0")] {
            items.push(EffectiveItem {
                key: key.to_owned(),
                ..hours_item(value)
            });
        }
        assert_eq!(
            (
                decide(&at, &items, &locked, &checks),
                decide(&at, &items, &UserState::default(), &checks)
            ),
            (
                refused(THRESHOLD, Door::LdapBind, None),
                refused(LOGIN_HOURS, Door::LdapBind, Some(OUTSIDE))
            ),
            "locked and outside the hours: the lock is named; not locked: the hours"
        );
    }
}
