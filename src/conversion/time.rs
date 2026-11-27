//! Time crate type implementations (Date, Time, PrimitiveDateTime, OffsetDateTime).

#[cfg(test)]
#[path = "time_tests.rs"]
mod tests;

use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

use super::std_time::{INTERVAL_TEXT_UNSUPPORTED, Interval};
use super::{FromWireValue, PG_EPOCH_JULIAN_DAY, ToWireValue};

impl FromWireValue<'_> for time::Date {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::DATE {
            return Err(Error::Decode(format!("cannot decode oid {} as Date", oid)));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
        let format = time::macros::format_description!("[year]-[month]-[day]");
        time::Date::parse(s, &format).map_err(|e| Error::Decode(format!("invalid date: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::DATE {
            return Err(Error::Decode(format!("cannot decode oid {} as Date", oid)));
        }
        let arr: [u8; 4] = bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!("invalid Date length: {}", bytes.len()))
        })?;
        let pg_days = i32::from_be_bytes(arr);
        let julian_day = pg_days
            .checked_add(PG_EPOCH_JULIAN_DAY)
            .ok_or_else(|| Error::Decode(format!("date out of range: {} days", pg_days)))?;
        time::Date::from_julian_day(julian_day)
            .map_err(|e| Error::Decode(format!("invalid date: {}", e)))
    }
}

impl ToWireValue for time::Date {
    const NATURAL_OID: Oid = oid::DATE;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::DATE => {
                let pg_days = self.to_julian_day() - PG_EPOCH_JULIAN_DAY;
                buf.extend_from_slice(&4_i32.to_be_bytes());
                buf.extend_from_slice(&pg_days.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl FromWireValue<'_> for time::Time {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIME {
            return Err(Error::Decode(format!("cannot decode oid {} as Time", oid)));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
        let format_with_micro =
            time::macros::format_description!("[hour]:[minute]:[second].[subsecond]");
        let format_without_micro = time::macros::format_description!("[hour]:[minute]:[second]");
        time::Time::parse(s, &format_with_micro)
            .or_else(|_| time::Time::parse(s, &format_without_micro))
            .map_err(|e| Error::Decode(format!("invalid time: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIME {
            return Err(Error::Decode(format!("cannot decode oid {} as Time", oid)));
        }
        let arr: [u8; 8] = bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!("invalid Time length: {}", bytes.len()))
        })?;
        let usecs = i64::from_be_bytes(arr);
        // Convert microseconds to hours, minutes, seconds, microseconds
        let hours = (usecs / 3_600_000_000) as u8;
        let remaining = usecs % 3_600_000_000;
        let minutes = (remaining / 60_000_000) as u8;
        let remaining = remaining % 60_000_000;
        let seconds = (remaining / 1_000_000) as u8;
        let micros = (remaining % 1_000_000) as u32;
        time::Time::from_hms_micro(hours, minutes, seconds, micros)
            .map_err(|e| Error::Decode(format!("invalid time: {}", e)))
    }
}

impl ToWireValue for time::Time {
    const NATURAL_OID: Oid = oid::TIME;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIME => {
                if !self.nanosecond().is_multiple_of(1000) {
                    return Err(Error::Encode("Time has sub-microsecond precision".into()));
                }
                let (hour, minute, second, nano) = self.as_hms_nano();
                let usecs = (hour as i64) * 3_600_000_000
                    + (minute as i64) * 60_000_000
                    + (second as i64) * 1_000_000
                    + (nano as i64) / 1000;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl FromWireValue<'_> for time::PrimitiveDateTime {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if !matches!(oid, oid::TIMESTAMP | oid::TIMESTAMPTZ) {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Timestamp",
                oid
            )));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
        // Remove timezone suffix if present for TIMESTAMPTZ
        let s = s
            .find(['+', '-'])
            .filter(|&pos| pos > 10) // Make sure it's not the date separator
            .map(|pos| &s[..pos])
            .unwrap_or(s);
        let format_with_micro = time::macros::format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond]"
        );
        let format_without_micro =
            time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
        time::PrimitiveDateTime::parse(s, &format_with_micro)
            .or_else(|_| time::PrimitiveDateTime::parse(s, &format_without_micro))
            .map_err(|e| Error::Decode(format!("invalid timestamp: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if !matches!(oid, oid::TIMESTAMP | oid::TIMESTAMPTZ) {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Timestamp",
                oid
            )));
        }
        let arr: [u8; 8] = bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!("invalid Timestamp length: {}", bytes.len()))
        })?;
        let usecs = i64::from_be_bytes(arr);
        // PostgreSQL epoch is 2000-01-01 00:00:00
        const PG_EPOCH: time::PrimitiveDateTime = time::macros::datetime!(2000-01-01 00:00:00);
        PG_EPOCH
            .checked_add(time::Duration::microseconds(usecs))
            .ok_or_else(|| Error::Decode("timestamp overflow".into()))
    }
}

impl ToWireValue for time::PrimitiveDateTime {
    const NATURAL_OID: Oid = oid::TIMESTAMP;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIMESTAMP | oid::TIMESTAMPTZ => {
                if !self.nanosecond().is_multiple_of(1000) {
                    return Err(Error::Encode(
                        "PrimitiveDateTime has sub-microsecond precision".into(),
                    ));
                }
                // Calculate microseconds since PostgreSQL epoch (2000-01-01 00:00:00)
                const PG_EPOCH: time::PrimitiveDateTime =
                    time::macros::datetime!(2000-01-01 00:00:00);
                let duration = *self - PG_EPOCH;
                let usecs = duration.whole_microseconds() as i64;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl FromWireValue<'_> for time::OffsetDateTime {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIMESTAMPTZ {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as OffsetDateTime",
                oid
            )));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
        // PostgreSQL returns TIMESTAMPTZ with offset like "2024-01-15 10:30:00+00"
        // Try various formats
        let formats = [
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond][offset_hour]:[offset_minute]",
            "[year]-[month]-[day] [hour]:[minute]:[second][offset_hour]:[offset_minute]",
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond][offset_hour]",
            "[year]-[month]-[day] [hour]:[minute]:[second][offset_hour]",
        ];
        for fmt in &formats {
            if let Ok(format) = time::format_description::parse_borrowed::<3>(fmt)
                && let Ok(dt) = time::OffsetDateTime::parse(s, &format)
            {
                return Ok(dt);
            }
        }
        Err(Error::Decode(format!("invalid timestamptz: {}", s)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIMESTAMPTZ {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as OffsetDateTime",
                oid
            )));
        }
        let arr: [u8; 8] = bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!("invalid Timestamp length: {}", bytes.len()))
        })?;
        let usecs = i64::from_be_bytes(arr);
        // PostgreSQL stores TIMESTAMPTZ as UTC microseconds since 2000-01-01 00:00:00 UTC
        const PG_EPOCH: time::OffsetDateTime = time::macros::datetime!(2000-01-01 00:00:00 UTC);
        PG_EPOCH
            .checked_add(time::Duration::microseconds(usecs))
            .ok_or_else(|| Error::Decode("timestamp overflow".into()))
    }
}

impl ToWireValue for time::OffsetDateTime {
    const NATURAL_OID: Oid = oid::TIMESTAMPTZ;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIMESTAMP | oid::TIMESTAMPTZ => {
                if !self.nanosecond().is_multiple_of(1000) {
                    return Err(Error::Encode(
                        "OffsetDateTime has sub-microsecond precision".into(),
                    ));
                }
                // Convert to UTC and calculate microseconds since PostgreSQL epoch
                let utc = self.to_offset(time::UtcOffset::UTC);
                const PG_EPOCH: time::OffsetDateTime =
                    time::macros::datetime!(2000-01-01 00:00:00 UTC);
                let duration = utc - PG_EPOCH;
                let usecs = duration.whole_microseconds() as i64;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

fn signed_duration_from_interval(interval: Interval) -> Result<time::SignedDuration> {
    interval
        .microseconds_only("SignedDuration")
        .map(time::SignedDuration::microseconds)
}

impl FromWireValue<'_> for time::SignedDuration {
    fn from_text(oid: Oid, _bytes: &[u8]) -> Result<Self> {
        if oid != oid::INTERVAL {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as SignedDuration",
                oid
            )));
        }
        Err(Error::Decode(INTERVAL_TEXT_UNSUPPORTED.into()))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::INTERVAL {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as SignedDuration",
                oid
            )));
        }
        signed_duration_from_interval(Interval::from_binary(oid, bytes)?)
    }
}

impl ToWireValue for time::SignedDuration {
    const NATURAL_OID: Oid = oid::INTERVAL;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::INTERVAL => {
                Interval::from_nanos(0, 0, self.whole_nanoseconds())?.encode(target_oid, buf)
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}
