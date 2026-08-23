//! Civil dates, in UTC (`ID-007`, #112).
//!
//! A generated ePID carries the day-of-year and year on which the host was
//! "activated", drawn uniformly between the claimed build's release date and
//! now. That needs three things a `no_std` crate has no library for: a date,
//! the number of days between two dates, and a **1-based** day-of-year
//! (`ID-004`, #109).
//!
//! # Two things that are easy to get wrong and both have been
//!
//! * **The day-of-year is 1-based.** vlmcsd emits `tm_yday + 1`, and License
//!   Manager's ePID *validator* does `date.AddDays(dayOfYear - 1)` and rejects
//!   anything that does not round-trip against .NET's 1-based `DayOfYear` — so
//!   a `000` is treated as malformed. py-kms is the outlier and is wrong.
//! * **The calculation is in UTC.** py-kms uses `time.mktime` on local time,
//!   which makes its day-of-year depend on the server's timezone and on whether
//!   daylight saving was in effect — so the same host produces a different ePID
//!   in March than in December.
//!
//! The conversions are Howard Hinnant's `days_from_civil` / `civil_from_days`,
//! which are exact integer arithmetic over the proleptic Gregorian calendar with
//! no floating point and no lookup tables.

/// Days from 1970-01-01 to 0000-03-01, the shifted epoch Hinnant's algorithm
/// counts from.
const EPOCH_SHIFT: i32 = 719_468;

/// Days in a 400-year Gregorian era.
const DAYS_PER_ERA: i32 = 146_097;

/// A calendar date in UTC.
///
/// Deliberately not a timestamp. The values this holds are release dates and
/// activation dates, which are dates rather than instants — a release date with
/// a time of day would invite the question of which timezone it was in, and
/// that question is exactly what py-kms gets wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: i32,
    month: u8,
    day: u8,
}

impl Date {
    /// Construct a date, checking that it exists.
    ///
    /// Returns `None` for a month outside `1..=12` or a day outside the month's
    /// length — including 29 February in a common year, which is the case a
    /// bounds check on `1..=31` would let through.
    #[must_use]
    pub const fn new(year: i32, month: u8, day: u8) -> Option<Self> {
        if month < 1 || month > 12 || day < 1 {
            return None;
        }
        if day > days_in_month(year, month) {
            return None;
        }
        Some(Self { year, month, day })
    }

    /// The year.
    #[must_use]
    pub const fn year(self) -> i32 {
        self.year
    }

    /// The month, `1..=12`.
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }

    /// The day of the month, `1..=31`.
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }

    /// Days since 1970-01-01, negative before it.
    #[must_use]
    pub const fn days_since_epoch(self) -> i32 {
        let year = if self.month <= 2 {
            self.year.saturating_sub(1)
        } else {
            self.year
        };
        let era = year.div_euclid(400);
        let year_of_era = year.saturating_sub(era.saturating_mul(400));

        let shifted_month = if self.month > 2 {
            (self.month as i32).saturating_sub(3)
        } else {
            (self.month as i32).saturating_add(9)
        };
        let day_of_year = (153_i32.saturating_mul(shifted_month).saturating_add(2))
            .div_euclid(5)
            .saturating_add(self.day as i32)
            .saturating_sub(1);

        let day_of_era = year_of_era
            .saturating_mul(365)
            .saturating_add(year_of_era.div_euclid(4))
            .saturating_sub(year_of_era.div_euclid(100))
            .saturating_add(day_of_year);

        era.saturating_mul(DAYS_PER_ERA)
            .saturating_add(day_of_era)
            .saturating_sub(EPOCH_SHIFT)
    }

    /// The date `days` after 1970-01-01.
    ///
    /// Not `const`, because the month and day come back from the algorithm as
    /// `i32` and narrowing them needs `TryFrom`, which is not usable in a
    /// `const fn`. Only [`Date::new`] has to be `const` — it is what the
    /// generated tables call.
    #[must_use]
    pub fn from_days_since_epoch(days: i32) -> Self {
        let shifted = days.saturating_add(EPOCH_SHIFT);
        let era = shifted.div_euclid(DAYS_PER_ERA);
        let day_of_era = shifted.saturating_sub(era.saturating_mul(DAYS_PER_ERA));

        let year_of_era = day_of_era
            .saturating_sub(day_of_era.div_euclid(1460))
            .saturating_add(day_of_era.div_euclid(36524))
            .saturating_sub(day_of_era.div_euclid(DAYS_PER_ERA.saturating_sub(1)))
            .div_euclid(365);
        let year = year_of_era.saturating_add(era.saturating_mul(400));

        let day_of_year = day_of_era.saturating_sub(
            year_of_era
                .saturating_mul(365)
                .saturating_add(year_of_era.div_euclid(4))
                .saturating_sub(year_of_era.div_euclid(100)),
        );
        let shifted_month = day_of_year
            .saturating_mul(5)
            .saturating_add(2)
            .div_euclid(153);
        let day = day_of_year
            .saturating_sub(
                153_i32
                    .saturating_mul(shifted_month)
                    .saturating_add(2)
                    .div_euclid(5),
            )
            .saturating_add(1);
        let month = if shifted_month < 10 {
            shifted_month.saturating_add(3)
        } else {
            shifted_month.saturating_sub(9)
        };
        let year = if month <= 2 {
            year.saturating_add(1)
        } else {
            year
        };

        // Both are in range by construction of the algorithm; the fallbacks
        // keep the conversion total without an unwrap, and would produce a
        // date `new` refuses rather than a plausible wrong one.
        Self {
            year,
            month: u8::try_from(month).unwrap_or(0),
            day: u8::try_from(day).unwrap_or(0),
        }
    }

    /// The **1-based** day of the year (`ID-004`, #109).
    ///
    /// 1 on 1 January. A zero here is what License Manager's validator treats
    /// as malformed, and is what py-kms emits.
    #[must_use]
    pub fn day_of_year(self) -> u16 {
        let Some(january_first) = Self::new(self.year, 1, 1) else {
            return 1;
        };
        let elapsed = self
            .days_since_epoch()
            .saturating_sub(january_first.days_since_epoch());
        // `elapsed` is 0 on 1 January, and the day-of-year is 1-based.
        u16::try_from(elapsed.saturating_add(1)).unwrap_or(1)
    }
}

impl core::fmt::Display for Date {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Whether a year has a 29 February.
#[must_use]
pub const fn is_leap_year(year: i32) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// How many days a month has.
#[must_use]
pub const fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{Date, days_in_month, is_leap_year};
    use alloc::format;

    #[test]
    fn the_epoch_is_day_zero() {
        assert_eq!(Date::new(1970, 1, 1).unwrap().days_since_epoch(), 0);
        assert_eq!(
            Date::from_days_since_epoch(0),
            Date::new(1970, 1, 1).unwrap()
        );
    }

    /// Known values, so a sign error or an off-by-one in the era arithmetic
    /// cannot hide behind a self-consistent round trip.
    #[test]
    fn known_dates_convert_to_known_day_numbers() {
        for (year, month, day, days) in [
            (1970, 1, 1, 0_i32),
            (1970, 1, 2, 1),
            (1969, 12, 31, -1),
            (1601, 1, 1, -134_774),
            (2000, 1, 1, 10_957),
            (2000, 2, 29, 11_016),
            (2024, 10, 1, 19_997),
            (2026, 2, 10, 20_494),
        ] {
            let date = Date::new(year, month, day).unwrap();
            assert_eq!(date.days_since_epoch(), days, "{date}");
            assert_eq!(Date::from_days_since_epoch(days), date, "{days}");
        }
    }

    #[test]
    fn conversion_round_trips_across_a_wide_range() {
        // Every day from 1900 to 2100, which covers every leap-year rule.
        let start = Date::new(1900, 1, 1).unwrap().days_since_epoch();
        let end = Date::new(2100, 12, 31).unwrap().days_since_epoch();
        for days in start..=end {
            let date = Date::from_days_since_epoch(days);
            assert_eq!(date.days_since_epoch(), days, "{date}");
        }
    }

    /// `ID-004` (#109). The day-of-year is 1-based: License Manager's ePID
    /// validator does `date.AddDays(dayOfYear - 1)` and rejects anything that
    /// does not round-trip against .NET's 1-based `DayOfYear`, so a `000` is
    /// malformed. py-kms is the outlier.
    #[test]
    fn the_day_of_year_is_one_based() {
        assert_eq!(Date::new(2024, 1, 1).unwrap().day_of_year(), 1);
        assert_eq!(Date::new(2024, 1, 2).unwrap().day_of_year(), 2);
        assert_eq!(Date::new(2024, 2, 29).unwrap().day_of_year(), 60);
        assert_eq!(Date::new(2024, 12, 31).unwrap().day_of_year(), 366);
        // A common year is one day shorter, and 29 February does not exist.
        assert_eq!(Date::new(2023, 12, 31).unwrap().day_of_year(), 365);
        assert_eq!(Date::new(2023, 3, 1).unwrap().day_of_year(), 60);

        // Never zero, for any date in any year.
        for year in 1990..2100 {
            assert_eq!(Date::new(year, 1, 1).unwrap().day_of_year(), 1);
            let last = Date::new(year, 12, 31).unwrap().day_of_year();
            assert_eq!(last, if is_leap_year(year) { 366 } else { 365 }, "{year}");
        }
    }

    /// A bounds check on `1..=31` would accept 29 February in a common year and
    /// 31 April, both of which would then produce a wrong day-of-year rather
    /// than an error.
    #[test]
    fn impossible_dates_are_refused() {
        assert!(Date::new(2023, 2, 29).is_none(), "2023 is not a leap year");
        assert!(Date::new(2024, 2, 29).is_some(), "2024 is");
        assert!(Date::new(1900, 2, 29).is_none(), "1900 is not, despite /4");
        assert!(Date::new(2000, 2, 29).is_some(), "2000 is, despite /100");

        assert!(Date::new(2024, 4, 31).is_none());
        assert!(Date::new(2024, 0, 1).is_none());
        assert!(Date::new(2024, 13, 1).is_none());
        assert!(Date::new(2024, 1, 0).is_none());
        assert!(Date::new(2024, 1, 32).is_none());
    }

    #[test]
    fn the_leap_year_rule_is_the_gregorian_one() {
        for (year, leap) in [
            (2024, true),
            (2023, false),
            (2000, true),
            (1900, false),
            (2100, false),
            (1600, true),
        ] {
            assert_eq!(is_leap_year(year), leap, "{year}");
            assert_eq!(days_in_month(year, 2), if leap { 29 } else { 28 });
        }
        assert_eq!(days_in_month(2024, 1), 31);
        assert_eq!(days_in_month(2024, 4), 30);
        assert_eq!(days_in_month(2024, 13), 0, "not a month");
    }

    #[test]
    fn display_is_iso_8601() {
        assert_eq!(format!("{}", Date::new(2024, 10, 1).unwrap()), "2024-10-01");
        assert_eq!(format!("{}", Date::new(999, 1, 2).unwrap()), "0999-01-02");
    }
}
