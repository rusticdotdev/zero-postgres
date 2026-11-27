#[cfg(test)]
#[path = "std_time_tests.rs"]
mod tests;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

use super::{FromWireValue, ToWireValue};

const NANOS_PER_USEC: i128 = 1_000;

const USECS_PER_SEC: i128 = 1_000_000;

const USECS_PER_MINUTE: i128 = 60 * USECS_PER_SEC;

const USECS_PER_HOUR: i128 = 60 * USECS_PER_MINUTE;

const USECS_PER_DAY: i128 = 24 * USECS_PER_HOUR;

const PG_EPOCH_UNIX_USECS: i128 = 946_684_800 * USECS_PER_SEC;

const MAX_YEAR: u64 = 999_999;

pub(super) const INTERVAL_TEXT_UNSUPPORTED: &str =
    "interval text format is not supported; use the extended query protocol";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Interval {
    pub months: i32,
    pub days: i32,
    pub microseconds: i64,
}

impl Interval {
    pub(super) fn from_nanos(months: i64, days: i64, nanos: i128) -> Result<Self> {
        if nanos % NANOS_PER_USEC != 0 {
            return Err(Error::Encode(format!(
                "interval has sub-microsecond precision: {} nanoseconds",
                nanos
            )));
        }
        let out_of_range = || Error::Encode("interval out of range".into());
        Ok(Self {
            months: i32::try_from(months).map_err(|_unhelpful_err| out_of_range())?,
            days: i32::try_from(days).map_err(|_unhelpful_err| out_of_range())?,
            microseconds: i64::try_from(nanos / NANOS_PER_USEC)
                .map_err(|_unhelpful_err| out_of_range())?,
        })
    }

    pub(super) fn microseconds_only(&self, type_name: &str) -> Result<i64> {
        if self.months != 0 || self.days != 0 {
            return Err(Error::Decode(format!(
                "interval with {} months and {} days cannot be decoded as {}; decode as Interval instead",
                self.months, self.days, type_name
            )));
        }
        Ok(self.microseconds)
    }
}

impl FromWireValue<'_> for Interval {
    fn from_text(oid: Oid, _bytes: &[u8]) -> Result<Self> {
        if oid != oid::INTERVAL {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Interval",
                oid
            )));
        }
        Err(Error::Decode(INTERVAL_TEXT_UNSUPPORTED.into()))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::INTERVAL {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Interval",
                oid
            )));
        }
        let invalid_length = || Error::Decode(format!("invalid Interval length: {}", bytes.len()));
        let (microseconds, days_and_months) =
            bytes.split_first_chunk::<8>().ok_or_else(invalid_length)?;
        let (days, months) = days_and_months
            .split_first_chunk::<4>()
            .ok_or_else(invalid_length)?;
        let months: [u8; 4] = months
            .try_into()
            .map_err(|_unhelpful_err| invalid_length())?;
        Ok(Self {
            months: i32::from_be_bytes(months),
            days: i32::from_be_bytes(*days),
            microseconds: i64::from_be_bytes(*microseconds),
        })
    }
}

impl ToWireValue for Interval {
    const NATURAL_OID: Oid = oid::INTERVAL;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::INTERVAL => {
                buf.extend_from_slice(&16_i32.to_be_bytes());
                buf.extend_from_slice(&self.microseconds.to_be_bytes());
                buf.extend_from_slice(&self.days.to_be_bytes());
                buf.extend_from_slice(&self.months.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

fn parse_digits(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0_u64, |value, &byte| {
        let digit = byte.checked_sub(b'0').filter(|&digit| digit <= 9)?;
        value.checked_mul(10)?.checked_add(u64::from(digit))
    })
}

fn parse_two_digits(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != 2 {
        return None;
    }
    parse_digits(bytes)
}

fn parse_sexagesimal(bytes: &[u8]) -> Option<u64> {
    parse_two_digits(bytes).filter(|&value| value < 60)
}

fn parse_seconds_usecs(bytes: &[u8]) -> Option<u64> {
    let mut fields = bytes.splitn(2, |&byte| byte == b'.');
    let seconds = parse_sexagesimal(fields.next()?)?;
    let fraction_usecs = match fields.next() {
        Some(fraction) => {
            let scale = 10_u64.pow(6_u32.checked_sub(u32::try_from(fraction.len()).ok()?)?);
            parse_digits(fraction)? * scale
        }
        None => 0,
    };
    Some(seconds * 1_000_000 + fraction_usecs)
}

fn parse_time_usecs(bytes: &[u8]) -> Option<i128> {
    let mut fields = bytes.split(|&byte| byte == b':');
    let hours = parse_digits(fields.next()?)?;
    let minutes = parse_sexagesimal(fields.next()?)?;
    let seconds_usecs = parse_seconds_usecs(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    Some(
        i128::from(hours) * USECS_PER_HOUR
            + i128::from(minutes) * USECS_PER_MINUTE
            + i128::from(seconds_usecs),
    )
}

fn parse_offset_usecs(bytes: &[u8]) -> Option<i128> {
    let (sign, digits) = bytes.split_first()?;
    let mut fields = digits.split(|&byte| byte == b':');
    let hours = parse_two_digits(fields.next()?)?;
    let minutes = match fields.next() {
        Some(field) => parse_sexagesimal(field)?,
        None => 0,
    };
    let seconds = match fields.next() {
        Some(field) => parse_sexagesimal(field)?,
        None => 0,
    };
    if fields.next().is_some() {
        return None;
    }
    let usecs = i128::from(hours) * USECS_PER_HOUR
        + i128::from(minutes) * USECS_PER_MINUTE
        + i128::from(seconds) * USECS_PER_SEC;
    match sign {
        b'+' => Some(usecs),
        b'-' => Some(-usecs),
        _ => None,
    }
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u64) -> u64 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 31,
    }
}

fn unix_days(year: i64, month: u64, day: u64) -> i64 {
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year.rem_euclid(400);
    let shifted_month = (month + 9) % 12;
    let day_of_year = ((153 * shifted_month + 2) / 5 + day - 1) as i64;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn parse_timestamptz_unix_usecs(bytes: &[u8]) -> Option<i128> {
    let (text, is_bc) = match bytes.strip_suffix(b" BC") {
        Some(text) => (text, true),
        None => (bytes, false),
    };
    let mut fields = text.splitn(2, |&byte| byte == b' ');
    let mut date_fields = fields.next()?.split(|&byte| byte == b'-');
    let time_and_offset = fields.next()?;

    let era_year = date_fields
        .next()
        .filter(|field| field.len() >= 4)
        .and_then(parse_digits)
        .filter(|year| (1..=MAX_YEAR).contains(year))?;
    let month = parse_two_digits(date_fields.next()?).filter(|month| (1..=12).contains(month))?;
    let day = parse_two_digits(date_fields.next()?)?;
    if date_fields.next().is_some() {
        return None;
    }
    let year = if is_bc {
        1 - i64::try_from(era_year).ok()?
    } else {
        i64::try_from(era_year).ok()?
    };
    if !(1..=days_in_month(year, month)).contains(&day) {
        return None;
    }

    let offset_start = time_and_offset
        .iter()
        .position(|&byte| matches!(byte, b'+' | b'-'))?;
    let (time, offset) = time_and_offset.split_at(offset_start);
    if time.get(2) != Some(&b':') {
        return None;
    }
    let time_usecs = parse_time_usecs(time).filter(|&usecs| usecs < USECS_PER_DAY)?;
    let offset_usecs = parse_offset_usecs(offset)?;

    Some(i128::from(unix_days(year, month, day)) * USECS_PER_DAY + time_usecs - offset_usecs)
}

fn system_time_from_unix_usecs(unix_usecs: i128) -> Result<SystemTime> {
    let magnitude = unix_usecs.unsigned_abs();
    let secs = u64::try_from(magnitude / 1_000_000).ok();
    let nanos = (magnitude % 1_000_000 * 1_000) as u32;
    secs.map(|secs| Duration::new(secs, nanos))
        .and_then(|distance| {
            if unix_usecs < 0 {
                UNIX_EPOCH.checked_sub(distance)
            } else {
                UNIX_EPOCH.checked_add(distance)
            }
        })
        .ok_or_else(|| Error::Decode("timestamp overflow".into()))
}

impl FromWireValue<'_> for SystemTime {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIMESTAMPTZ {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as SystemTime",
                oid
            )));
        }
        if matches!(bytes, b"infinity" | b"-infinity") {
            return Err(Error::Decode("infinite timestamptz".into()));
        }
        let unix_usecs = parse_timestamptz_unix_usecs(bytes).ok_or_else(|| {
            Error::Decode(format!(
                "invalid timestamptz: {:?}",
                String::from_utf8_lossy(bytes)
            ))
        })?;
        system_time_from_unix_usecs(unix_usecs)
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIMESTAMPTZ {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as SystemTime",
                oid
            )));
        }
        let arr: [u8; 8] = bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!("invalid Timestamp length: {}", bytes.len()))
        })?;
        let usecs = i64::from_be_bytes(arr);
        if matches!(usecs, i64::MAX | i64::MIN) {
            return Err(Error::Decode("infinite timestamptz".into()));
        }
        system_time_from_unix_usecs(i128::from(usecs) + PG_EPOCH_UNIX_USECS)
    }
}

impl ToWireValue for SystemTime {
    const NATURAL_OID: Oid = oid::TIMESTAMPTZ;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIMESTAMPTZ => {
                let unix_nanos = match self.duration_since(UNIX_EPOCH) {
                    Ok(distance) => distance.as_nanos() as i128,
                    Err(e) => -(e.duration().as_nanos() as i128),
                };
                if unix_nanos % NANOS_PER_USEC != 0 {
                    return Err(Error::Encode(
                        "SystemTime has sub-microsecond precision".into(),
                    ));
                }
                let usecs = i64::try_from(unix_nanos / NANOS_PER_USEC - PG_EPOCH_UNIX_USECS)
                    .ok()
                    .filter(|usecs| !matches!(*usecs, i64::MAX | i64::MIN))
                    .ok_or_else(|| Error::Encode("timestamp out of range".into()))?;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl FromWireValue<'_> for Duration {
    fn from_text(oid: Oid, _bytes: &[u8]) -> Result<Self> {
        if oid != oid::INTERVAL {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Duration",
                oid
            )));
        }
        Err(Error::Decode(INTERVAL_TEXT_UNSUPPORTED.into()))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::INTERVAL {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Duration",
                oid
            )));
        }
        duration_from_interval(Interval::from_binary(oid, bytes)?)
    }
}

fn duration_from_interval(interval: Interval) -> Result<Duration> {
    u64::try_from(interval.microseconds_only("Duration")?)
        .map(Duration::from_micros)
        .map_err(|_unhelpful_err| {
            Error::Decode(
                "negative interval cannot be decoded as Duration; decode as Interval instead"
                    .into(),
            )
        })
}

impl ToWireValue for Duration {
    const NATURAL_OID: Oid = oid::INTERVAL;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::INTERVAL => {
                Interval::from_nanos(0, 0, self.as_nanos() as i128)?.encode(target_oid, buf)
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}
