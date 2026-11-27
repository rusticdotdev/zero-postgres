//! Jiff crate type implementations (civil::Date, civil::Time, civil::DateTime, Timestamp).

#[cfg(test)]
#[path = "jiff_tests.rs"]
mod tests;

use jiff::civil::{Date, DateTime, Time};
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Span, Timestamp, ZonedDateTime};

use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

use super::std_time::{INTERVAL_TEXT_UNSUPPORTED, Interval};
use super::{FromWireValue, ToWireValue};

const PG_EPOCH: Date = jiff::civil::date(2000, 1, 1);

const PG_EPOCH_DT: DateTime = PG_EPOCH.at(0, 0, 0, 0);

const PG_EPOCH_TS: Timestamp = Timestamp::constant(946_684_800, 0);

#[cfg(test)]
const USECS_PER_SEC: i64 = 1_000_000;

#[cfg(test)]
const USECS_PER_DAY: i64 = 86_400_000_000;

impl FromWireValue<'_> for Date {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::DATE {
            return Err(Error::Decode(format!("cannot decode oid {} as Date", oid)));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
        Date::strptime("%Y-%m-%d", s).map_err(|e| Error::Decode(format!("invalid date: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::DATE {
            return Err(Error::Decode(format!("cannot decode oid {} as Date", oid)));
        }
        let arr: [u8; 4] = bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!("invalid Date length: {}", bytes.len()))
        })?;
        let pg_days = i32::from_be_bytes(arr);
        Span::new()
            .try_days(pg_days)
            .and_then(|days| PG_EPOCH.checked_add(days))
            .map_err(|_unhelpful_err| Error::Decode(format!("date out of range: {} days", pg_days)))
    }
}

impl ToWireValue for Date {
    const NATURAL_OID: Oid = oid::DATE;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::DATE => {
                let pg_days = (self.duration_since(PG_EPOCH).as_hours() / 24) as i32;
                buf.extend_from_slice(&4_i32.to_be_bytes());
                buf.extend_from_slice(&pg_days.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl FromWireValue<'_> for Time {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIME {
            return Err(Error::Decode(format!("cannot decode oid {} as Time", oid)));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
        Time::strptime("%H:%M:%S%.f", s).map_err(|e| Error::Decode(format!("invalid time: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIME {
            return Err(Error::Decode(format!("cannot decode oid {} as Time", oid)));
        }
        let arr: [u8; 8] = bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!("invalid Time length: {}", bytes.len()))
        })?;
        let usecs = i64::from_be_bytes(arr);
        Time::midnight()
            .checked_add(SignedDuration::from_micros(usecs))
            .map_err(|_unhelpful_err| Error::Decode("invalid time".into()))
    }
}

impl ToWireValue for Time {
    const NATURAL_OID: Oid = oid::TIME;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIME => {
                if self.subsec_nanosecond() % 1000 != 0 {
                    return Err(Error::Encode("Time has sub-microsecond precision".into()));
                }
                let usecs = self.duration_since(Time::midnight()).as_micros() as i64;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl FromWireValue<'_> for DateTime {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if !matches!(oid, oid::TIMESTAMP | oid::TIMESTAMPTZ) {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as DateTime",
                oid
            )));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
        let s = s
            .rfind(['+', '-'])
            .filter(|&pos| pos > 10)
            .map(|pos| &s[..pos])
            .unwrap_or(s);
        DateTime::strptime("%Y-%m-%d %H:%M:%S%.f", s)
            .map_err(|e| Error::Decode(format!("invalid timestamp: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if !matches!(oid, oid::TIMESTAMP | oid::TIMESTAMPTZ) {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as DateTime",
                oid
            )));
        }
        let arr: [u8; 8] = bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!("invalid Timestamp length: {}", bytes.len()))
        })?;
        let usecs = i64::from_be_bytes(arr);
        PG_EPOCH_DT
            .checked_add(SignedDuration::from_micros(usecs))
            .map_err(|_unhelpful_err| Error::Decode("timestamp overflow".into()))
    }
}

impl ToWireValue for DateTime {
    const NATURAL_OID: Oid = oid::TIMESTAMP;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIMESTAMP | oid::TIMESTAMPTZ => {
                if self.subsec_nanosecond() % 1000 != 0 {
                    return Err(Error::Encode(
                        "DateTime has sub-microsecond precision".into(),
                    ));
                }
                let usecs = self.duration_since(PG_EPOCH_DT).as_micros() as i64;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl FromWireValue<'_> for Timestamp {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIMESTAMPTZ {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Timestamp",
                oid
            )));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
        Timestamp::strptime("%Y-%m-%d %H:%M:%S%.f%:::z", s)
            .map_err(|e| Error::Decode(format!("invalid timestamptz: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIMESTAMPTZ {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Timestamp",
                oid
            )));
        }
        let arr: [u8; 8] = bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!("invalid Timestamp length: {}", bytes.len()))
        })?;
        let usecs = i64::from_be_bytes(arr);
        PG_EPOCH_TS
            .checked_add(SignedDuration::from_micros(usecs))
            .map_err(|_unhelpful_err| Error::Decode("timestamp overflow".into()))
    }
}

impl ToWireValue for Timestamp {
    const NATURAL_OID: Oid = oid::TIMESTAMPTZ;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIMESTAMP | oid::TIMESTAMPTZ => {
                if self.subsec_nanosecond() % 1000 != 0 {
                    return Err(Error::Encode(
                        "Timestamp has sub-microsecond precision".into(),
                    ));
                }
                let usecs = self.duration_since(PG_EPOCH_TS).as_micros() as i64;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl FromWireValue<'_> for ZonedDateTime {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIMESTAMPTZ {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as ZonedDateTime",
                oid
            )));
        }
        Timestamp::from_text(oid, bytes).map(|timestamp| timestamp.to_zoned_datetime(TimeZone::UTC))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::TIMESTAMPTZ {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as ZonedDateTime",
                oid
            )));
        }
        Timestamp::from_binary(oid, bytes)
            .map(|timestamp| timestamp.to_zoned_datetime(TimeZone::UTC))
    }
}

impl ToWireValue for ZonedDateTime {
    const NATURAL_OID: Oid = oid::TIMESTAMPTZ;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIMESTAMPTZ => {
                let timestamp = self.timestamp();
                if timestamp.subsec_nanosecond() % 1000 != 0 {
                    return Err(Error::Encode(
                        "ZonedDateTime has sub-microsecond precision".into(),
                    ));
                }
                let usecs = timestamp.duration_since(PG_EPOCH_TS).as_micros() as i64;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

fn span_from_interval(interval: Interval) -> Result<Span> {
    let signs = [
        i64::from(interval.months).signum(),
        i64::from(interval.days).signum(),
        interval.microseconds.signum(),
    ];
    if signs.contains(&1) && signs.contains(&-1) {
        return Err(Error::Decode(
            "interval with mixed signs cannot be decoded as Span; decode as Interval instead"
                .into(),
        ));
    }
    Span::new()
        .try_months(interval.months)
        .and_then(|span| span.try_days(interval.days))
        .and_then(|span| span.try_microseconds(interval.microseconds))
        .map_err(|e| {
            Error::Decode(format!(
                "interval out of range for Span: {}; decode as Interval instead",
                e
            ))
        })
}

impl FromWireValue<'_> for Span {
    fn from_text(oid: Oid, _bytes: &[u8]) -> Result<Self> {
        if oid != oid::INTERVAL {
            return Err(Error::Decode(format!("cannot decode oid {} as Span", oid)));
        }
        Err(Error::Decode(INTERVAL_TEXT_UNSUPPORTED.into()))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::INTERVAL {
            return Err(Error::Decode(format!("cannot decode oid {} as Span", oid)));
        }
        span_from_interval(Interval::from_binary(oid, bytes)?)
    }
}

impl ToWireValue for Span {
    const NATURAL_OID: Oid = oid::INTERVAL;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::INTERVAL => {
                let months = i64::from(self.get_years()) * 12 + i64::from(self.get_months());
                let days = i64::from(self.get_weeks()) * 7 + i64::from(self.get_days());
                let nanos = i128::from(self.get_hours()) * 3_600_000_000_000
                    + i128::from(self.get_minutes()) * 60_000_000_000
                    + i128::from(self.get_seconds()) * 1_000_000_000
                    + i128::from(self.get_milliseconds()) * 1_000_000
                    + i128::from(self.get_microseconds()) * 1_000
                    + i128::from(self.get_nanoseconds());
                Interval::from_nanos(months, days, nanos)?.encode(target_oid, buf)
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

fn signed_duration_from_interval(interval: Interval) -> Result<SignedDuration> {
    interval
        .microseconds_only("SignedDuration")
        .map(SignedDuration::from_micros)
}

impl FromWireValue<'_> for SignedDuration {
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

impl ToWireValue for SignedDuration {
    const NATURAL_OID: Oid = oid::INTERVAL;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::INTERVAL => Interval::from_nanos(0, 0, self.as_nanos())?.encode(target_oid, buf),
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}
