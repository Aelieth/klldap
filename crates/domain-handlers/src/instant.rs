use chrono::{DateTime, NaiveDateTime, Utc};
pub use jiff::{SignedDuration, Timestamp};

const SECOND: i128 = 1_000_000_000;

pub fn to_utc(at: Timestamp) -> DateTime<Utc> {
    let nanos = at.as_nanosecond();
    let (seconds, fraction) = (nanos.div_euclid(SECOND), nanos.rem_euclid(SECOND));
    DateTime::from_timestamp(seconds as i64, fraction as u32).unwrap_or_default()
}

pub fn to_naive(at: Timestamp) -> NaiveDateTime {
    to_utc(at).naive_utc()
}

/// A client's time: `None` outside jiff's range. A leap second is read as :59.
pub fn try_from_utc(at: DateTime<Utc>) -> Option<Timestamp> {
    let fraction = at.timestamp_subsec_nanos() % 1_000_000_000;
    Timestamp::new(at.timestamp(), fraction as i32).ok()
}

/// A stored time: outside jiff's range it is jiff's first or last instant.
pub fn from_utc(at: DateTime<Utc>) -> Timestamp {
    let end = if at.timestamp() < 0 {
        Timestamp::MIN
    } else {
        Timestamp::MAX
    };
    try_from_utc(at).unwrap_or(end)
}

pub fn from_naive(at: NaiveDateTime) -> Timestamp {
    from_utc(at.and_utc())
}

/// A stored RFC 3339 text, as jiff reads it; one only chrono can read is taken as a stored time.
pub fn from_stored_text(text: &str) -> Result<Timestamp, jiff::Error> {
    text.parse::<Timestamp>().or_else(|unread| {
        let stored = DateTime::parse_from_rfc3339(text).map_err(|_| unread)?;
        Ok(from_utc(stored.with_timezone(&Utc)))
    })
}

/// Counted downward from 1970, as chrono's `timestamp_micros` counts.
pub fn floor_micros(at: Timestamp) -> i64 {
    at.as_nanosecond().div_euclid(1_000) as i64
}

pub fn days(days: i64) -> SignedDuration {
    SignedDuration::from_hours(24 * days)
}

/// `at + by`, and `earlier` for `at - by`: both stop at jiff's first or last instant.
pub fn later(at: Timestamp, by: SignedDuration) -> Timestamp {
    let end = if by.is_negative() {
        Timestamp::MIN
    } else {
        Timestamp::MAX
    };
    at.checked_add(by).unwrap_or(end)
}

pub fn earlier(at: Timestamp, by: SignedDuration) -> Timestamp {
    let end = if by.is_negative() {
        Timestamp::MAX
    } else {
        Timestamp::MIN
    };
    at.checked_sub(by).unwrap_or(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const FIRST: i64 = -377_705_023_201;
    const LAST: i64 = 253_402_207_200;

    fn stored(seconds: i64, nanos: u32) -> NaiveDateTime {
        DateTime::from_timestamp(seconds, nanos)
            .unwrap()
            .naive_utc()
    }

    fn instant(seconds: i64, nanos: i32) -> Timestamp {
        Timestamp::new(seconds, nanos).unwrap()
    }

    #[test]
    fn test_jiffs_first_and_last_instants_are_the_ones_named_here() {
        assert_eq!(
            (Timestamp::MIN, Timestamp::MAX),
            (instant(FIRST, 0), instant(LAST, 999_999_999))
        );
    }

    #[test]
    fn test_an_instant_in_range_goes_to_chrono_and_back_unchanged() {
        let rows = [
            ("the epoch", 0, 0),
            ("half a microsecond before 1970", -1, 999_999_500),
            ("2038-01-19T03:14:08Z", 2_147_483_648, 0),
            ("jiff's first instant", FIRST, 0),
            ("jiff's last instant", LAST, 999_999_999),
        ];
        for (label, seconds, nanos) in rows {
            let at = instant(seconds, nanos as i32);
            assert_eq!(
                (to_naive(at), to_utc(at), from_naive(stored(seconds, nanos))),
                (stored(seconds, nanos), stored(seconds, nanos).and_utc(), at),
                "{label}"
            );
        }
    }

    #[test]
    fn test_a_stored_time_outside_the_range_is_the_nearest_end_and_a_clients_is_refused() {
        let rows = [
            (
                "a microsecond before the first",
                FIRST - 1,
                999_999_000,
                Timestamp::MIN,
            ),
            (
                "a microsecond after the last",
                LAST + 1,
                999,
                Timestamp::MAX,
            ),
            (
                "MySQL's largest DATETIME, 9999-12-31 23:59:59.999999",
                253_402_300_799,
                999_999_000,
                Timestamp::MAX,
            ),
            ("the year 20000", 568_971_820_800, 0, Timestamp::MAX),
            (
                "ten thousand years before the first",
                FIRST - 315_576_000_000,
                0,
                Timestamp::MIN,
            ),
        ];
        for (label, seconds, nanos, end) in rows {
            let at = stored(seconds, nanos);
            assert_eq!(
                (from_naive(at), try_from_utc(at.and_utc())),
                (end, None),
                "{label}"
            );
        }
    }

    #[test]
    fn test_a_stored_text_past_the_last_instant_is_the_last_instant() {
        let rows = [
            (
                "2023-11-14T22:13:20.5Z",
                Some(instant(1_700_000_000, 500_000_000)),
            ),
            ("9999-12-31T23:59:59.000000Z", Some(Timestamp::MAX)),
            ("soon", None),
        ];
        for (text, read) in rows {
            assert_eq!(from_stored_text(text).ok(), read, "{text}");
        }
    }

    #[test]
    fn test_a_leap_second_is_read_as_the_second_before_it() {
        let leap = stored(1_483_228_799, 1_500_000_000);
        let read = instant(1_483_228_799, 500_000_000);
        assert_eq!(
            (from_naive(leap), try_from_utc(leap.and_utc())),
            (read, Some(read))
        );
    }

    #[test]
    fn test_microseconds_count_downward_and_arithmetic_stops_at_the_ends() {
        let rows = [(0, 0, 0), (-1, 999_999_500, -1), (1, 1_999, 1_000_001)];
        for (seconds, nanos, micros) in rows {
            assert_eq!(
                floor_micros(instant(seconds, nanos)),
                micros,
                "{seconds} {nanos}"
            );
        }
        let day = days(1);
        assert_eq!(
            (
                day,
                later(instant(0, 0), day),
                earlier(instant(0, 0), day),
                later(Timestamp::MAX, day),
                earlier(Timestamp::MIN, day),
                later(Timestamp::MIN, days(-1)),
                earlier(Timestamp::MAX, days(-1)),
            ),
            (
                SignedDuration::from_secs(86_400),
                instant(86_400, 0),
                instant(-86_400, 0),
                Timestamp::MAX,
                Timestamp::MIN,
                Timestamp::MIN,
                Timestamp::MAX,
            )
        );
    }
}
