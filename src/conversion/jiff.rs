//! Jiff crate type implementations (civil::Date, civil::Time, civil::DateTime, Timestamp).

use jiff::civil::{Date, DateTime, Time};
use jiff::{SignedDuration, Span, Timestamp};

use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

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
    fn natural_oid(&self) -> Oid {
        oid::DATE
    }

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::DATE => {
                let pg_days = (self.duration_since(PG_EPOCH).as_hours() / 24) as i32;
                buf.extend_from_slice(&4_i32.to_be_bytes());
                buf.extend_from_slice(&pg_days.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(self.natural_oid(), target_oid)),
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
    fn natural_oid(&self) -> Oid {
        oid::TIME
    }

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIME => {
                let usecs = self.duration_since(Time::midnight()).as_micros() as i64;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(self.natural_oid(), target_oid)),
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
    fn natural_oid(&self) -> Oid {
        oid::TIMESTAMP
    }

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIMESTAMP | oid::TIMESTAMPTZ => {
                let usecs = self.duration_since(PG_EPOCH_DT).as_micros() as i64;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(self.natural_oid(), target_oid)),
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
    fn natural_oid(&self) -> Oid {
        oid::TIMESTAMPTZ
    }

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TIMESTAMP | oid::TIMESTAMPTZ => {
                let usecs = self.duration_since(PG_EPOCH_TS).as_micros() as i64;
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&usecs.to_be_bytes());
                Ok(())
            }
            _ => Err(Error::type_mismatch(self.natural_oid(), target_oid)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::{date, time};
    use jiff::tz::TimeZone;

    #[test]
    fn date_text() {
        let date = Date::from_text(oid::DATE, b"2024-01-15").unwrap();
        assert_eq!(date.year(), 2024);
        assert_eq!(date.month(), 1);
        assert_eq!(date.day(), 15);
    }

    #[test]
    fn date_binary() {
        // 2024-01-15 is 8780 days since 2000-01-01
        let days: i32 = 8780;
        let bytes = days.to_be_bytes();
        let date = Date::from_binary(oid::DATE, &bytes).unwrap();
        assert_eq!(date.year(), 2024);
        assert_eq!(date.month(), 1);
        assert_eq!(date.day(), 15);
    }

    #[test]
    fn date_binary_before_epoch() {
        assert_eq!(
            Date::from_binary(oid::DATE, &(-1_i32).to_be_bytes()).unwrap(),
            date(1999, 12, 31)
        );
        assert_eq!(
            Date::from_binary(oid::DATE, &(-36_524_i32).to_be_bytes()).unwrap(),
            date(1900, 1, 1)
        );
    }

    #[test]
    fn date_binary_infinity() {
        Date::from_binary(oid::DATE, &i32::MAX.to_be_bytes()).unwrap_err();
        Date::from_binary(oid::DATE, &i32::MIN.to_be_bytes()).unwrap_err();
    }

    #[test]
    fn date_roundtrip() {
        let original = date(2024, 1, 15);
        let mut buf = Vec::new();
        original.encode(original.natural_oid(), &mut buf).unwrap();
        let decoded = Date::from_binary(oid::DATE, &buf[4..]).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn date_roundtrip_before_epoch() {
        let original = date(1900, 1, 1);
        let mut buf = Vec::new();
        original.encode(original.natural_oid(), &mut buf).unwrap();
        assert_eq!(buf[4..], (-36_524_i32).to_be_bytes());
    }

    #[test]
    fn time_text() {
        let time = Time::from_text(oid::TIME, b"10:30:45").unwrap();
        assert_eq!(time.hour(), 10);
        assert_eq!(time.minute(), 30);
        assert_eq!(time.second(), 45);
    }

    #[test]
    fn time_text_with_micros() {
        let time = Time::from_text(oid::TIME, b"10:30:45.123456").unwrap();
        assert_eq!(time.hour(), 10);
        assert_eq!(time.minute(), 30);
        assert_eq!(time.second(), 45);
        assert_eq!(time.subsec_nanosecond(), 123456000);
    }

    #[test]
    fn time_binary() {
        // 10:30:45 = (10*3600 + 30*60 + 45) * 1_000_000 microseconds
        let usecs: i64 = (10 * 3600 + 30 * 60 + 45) * 1_000_000;
        let bytes = usecs.to_be_bytes();
        let time = Time::from_binary(oid::TIME, &bytes).unwrap();
        assert_eq!(time.hour(), 10);
        assert_eq!(time.minute(), 30);
        assert_eq!(time.second(), 45);
    }

    #[test]
    fn time_binary_out_of_range() {
        Time::from_binary(oid::TIME, &USECS_PER_DAY.to_be_bytes()).unwrap_err();
        Time::from_binary(oid::TIME, &(-1_i64).to_be_bytes()).unwrap_err();
    }

    #[test]
    fn time_roundtrip() {
        let original = time(10, 30, 45, 123_456_000);
        let mut buf = Vec::new();
        original.encode(original.natural_oid(), &mut buf).unwrap();
        let decoded = Time::from_binary(oid::TIME, &buf[4..]).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn timestamp_text() {
        let ts = DateTime::from_text(oid::TIMESTAMP, b"2024-01-15 10:30:45").unwrap();
        assert_eq!(ts.year(), 2024);
        assert_eq!(ts.month(), 1);
        assert_eq!(ts.day(), 15);
        assert_eq!(ts.hour(), 10);
        assert_eq!(ts.minute(), 30);
        assert_eq!(ts.second(), 45);
    }

    #[test]
    fn timestamp_text_strips_timezone() {
        assert_eq!(
            DateTime::from_text(oid::TIMESTAMPTZ, b"2024-01-15 10:30:45.123456+09").unwrap(),
            date(2024, 1, 15).at(10, 30, 45, 123_456_000)
        );
        assert_eq!(
            DateTime::from_text(oid::TIMESTAMPTZ, b"2024-01-15 10:30:45-05:30").unwrap(),
            date(2024, 1, 15).at(10, 30, 45, 0)
        );
    }

    #[test]
    fn timestamp_binary() {
        // 2024-01-15 10:30:45 UTC
        // Days since 2000-01-01: 8780
        let day_usecs: i64 = 8780 * USECS_PER_DAY;
        let time_usecs: i64 = (10 * 3600 + 30 * 60 + 45) * USECS_PER_SEC;
        let total_usecs = day_usecs + time_usecs;
        let bytes = total_usecs.to_be_bytes();
        let ts = DateTime::from_binary(oid::TIMESTAMP, &bytes).unwrap();
        assert_eq!(ts.year(), 2024);
        assert_eq!(ts.month(), 1);
        assert_eq!(ts.day(), 15);
        assert_eq!(ts.hour(), 10);
        assert_eq!(ts.minute(), 30);
        assert_eq!(ts.second(), 45);
    }

    #[test]
    fn timestamp_binary_before_epoch() {
        assert_eq!(
            DateTime::from_binary(oid::TIMESTAMP, &(-1_i64).to_be_bytes()).unwrap(),
            date(1999, 12, 31).at(23, 59, 59, 999_999_000)
        );
        assert_eq!(
            Timestamp::from_binary(oid::TIMESTAMPTZ, &(-1_i64).to_be_bytes()).unwrap(),
            date(1999, 12, 31)
                .at(23, 59, 59, 999_999_000)
                .to_zoned(TimeZone::UTC)
                .unwrap()
                .timestamp()
        );
    }

    #[test]
    fn timestamp_binary_infinity() {
        DateTime::from_binary(oid::TIMESTAMP, &i64::MAX.to_be_bytes()).unwrap_err();
        DateTime::from_binary(oid::TIMESTAMP, &i64::MIN.to_be_bytes()).unwrap_err();
        Timestamp::from_binary(oid::TIMESTAMPTZ, &i64::MAX.to_be_bytes()).unwrap_err();
        Timestamp::from_binary(oid::TIMESTAMPTZ, &i64::MIN.to_be_bytes()).unwrap_err();
    }

    #[test]
    fn timestamp_roundtrip() {
        let original = date(2024, 1, 15).at(10, 30, 45, 123_456_000);
        let mut buf = Vec::new();
        original.encode(original.natural_oid(), &mut buf).unwrap();
        let decoded = DateTime::from_binary(oid::TIMESTAMP, &buf[4..]).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn timestamp_roundtrip_before_epoch() {
        let original = date(1969, 7, 20).at(20, 17, 40, 123_456_000);
        let mut buf = Vec::new();
        original.encode(original.natural_oid(), &mut buf).unwrap();
        let decoded = DateTime::from_binary(oid::TIMESTAMP, &buf[4..]).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn timestamptz_text() {
        let expected = date(2024, 1, 15)
            .at(10, 30, 45, 0)
            .to_zoned(TimeZone::UTC)
            .unwrap()
            .timestamp();
        for text in [
            "2024-01-15 10:30:45+00",
            "2024-01-15 19:30:45+09",
            "2024-01-15 16:00:45+05:30",
            "2024-01-15 05:30:45-05",
        ] {
            assert_eq!(
                Timestamp::from_text(oid::TIMESTAMPTZ, text.as_bytes()).unwrap(),
                expected,
                "{text}"
            );
        }
        assert_eq!(
            Timestamp::from_text(oid::TIMESTAMPTZ, b"2024-01-15 10:30:45.123456+00").unwrap(),
            expected + SignedDuration::from_micros(123_456)
        );
        Timestamp::from_text(oid::TIMESTAMPTZ, b"infinity").unwrap_err();
    }

    #[test]
    fn timestamptz_binary() {
        let day_usecs: i64 = 8780 * USECS_PER_DAY;
        let time_usecs: i64 = (10 * 3600 + 30 * 60 + 45) * USECS_PER_SEC;
        let total_usecs = day_usecs + time_usecs;
        let bytes = total_usecs.to_be_bytes();
        let ts = Timestamp::from_binary(oid::TIMESTAMPTZ, &bytes)
            .unwrap()
            .to_zoned(TimeZone::UTC);
        assert_eq!(ts.year(), 2024);
        assert_eq!(ts.month(), 1);
        assert_eq!(ts.day(), 15);
        assert_eq!(ts.hour(), 10);
        assert_eq!(ts.minute(), 30);
        assert_eq!(ts.second(), 45);
    }

    #[test]
    fn timestamptz_roundtrip() {
        let original = Timestamp::from_microsecond(1_795_000_000_123_456).unwrap();
        let mut buf = Vec::new();
        original.encode(original.natural_oid(), &mut buf).unwrap();
        let decoded = Timestamp::from_binary(oid::TIMESTAMPTZ, &buf[4..]).unwrap();
        assert_eq!(original, decoded);
    }
}
