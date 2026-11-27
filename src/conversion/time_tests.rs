use super::*;

#[test]
fn date_text() {
    let date = time::Date::from_text(oid::DATE, b"2024-01-15").unwrap();
    assert_eq!(date.year(), 2024);
    assert_eq!(date.month() as u8, 1);
    assert_eq!(date.day(), 15);
}

#[test]
fn date_binary() {
    // 2024-01-15 is 8780 days since 2000-01-01
    let days: i32 = 8780;
    let bytes = days.to_be_bytes();
    let date = time::Date::from_binary(oid::DATE, &bytes).unwrap();
    assert_eq!(date.year(), 2024);
    assert_eq!(date.month() as u8, 1);
    assert_eq!(date.day(), 15);
}

#[test]
fn date_binary_infinity() {
    time::Date::from_binary(oid::DATE, &i32::MAX.to_be_bytes()).unwrap_err();
    time::Date::from_binary(oid::DATE, &i32::MIN.to_be_bytes()).unwrap_err();
}

#[test]
fn date_roundtrip() {
    let original = time::Date::from_calendar_date(2024, time::Month::January, 15).unwrap();
    let mut buf = Vec::new();
    original.encode(time::Date::NATURAL_OID, &mut buf).unwrap();
    let decoded = time::Date::from_binary(oid::DATE, &buf[4..]).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn time_text() {
    let time = time::Time::from_text(oid::TIME, b"10:30:45").unwrap();
    assert_eq!(time.hour(), 10);
    assert_eq!(time.minute(), 30);
    assert_eq!(time.second(), 45);
}

#[test]
fn time_text_with_micros() {
    let time = time::Time::from_text(oid::TIME, b"10:30:45.123456").unwrap();
    assert_eq!(time.hour(), 10);
    assert_eq!(time.minute(), 30);
    assert_eq!(time.second(), 45);
    assert_eq!(time.microsecond(), 123456);
}

#[test]
fn time_binary() {
    // 10:30:45 = (10*3600 + 30*60 + 45) * 1_000_000 microseconds
    let usecs: i64 = (10 * 3600 + 30 * 60 + 45) * 1_000_000;
    let bytes = usecs.to_be_bytes();
    let time = time::Time::from_binary(oid::TIME, &bytes).unwrap();
    assert_eq!(time.hour(), 10);
    assert_eq!(time.minute(), 30);
    assert_eq!(time.second(), 45);
}

#[test]
fn time_roundtrip() {
    let original = time::Time::from_hms_micro(10, 30, 45, 123456).unwrap();
    let mut buf = Vec::new();
    original.encode(time::Time::NATURAL_OID, &mut buf).unwrap();
    let decoded = time::Time::from_binary(oid::TIME, &buf[4..]).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn timestamp_text() {
    let ts = time::PrimitiveDateTime::from_text(oid::TIMESTAMP, b"2024-01-15 10:30:45").unwrap();
    assert_eq!(ts.year(), 2024);
    assert_eq!(ts.month() as u8, 1);
    assert_eq!(ts.day(), 15);
    assert_eq!(ts.hour(), 10);
    assert_eq!(ts.minute(), 30);
    assert_eq!(ts.second(), 45);
}

#[test]
fn timestamp_binary() {
    // 2024-01-15 10:30:45 UTC
    // Days since 2000-01-01: 8780
    // Time: 10:30:45 = 37845 seconds = 37845000000 microseconds
    let day_usecs: i64 = 8780 * 24 * 3600 * 1_000_000;
    let time_usecs: i64 = (10 * 3600 + 30 * 60 + 45) * 1_000_000;
    let total_usecs = day_usecs + time_usecs;
    let bytes = total_usecs.to_be_bytes();
    let ts = time::PrimitiveDateTime::from_binary(oid::TIMESTAMP, &bytes).unwrap();
    assert_eq!(ts.year(), 2024);
    assert_eq!(ts.month() as u8, 1);
    assert_eq!(ts.day(), 15);
    assert_eq!(ts.hour(), 10);
    assert_eq!(ts.minute(), 30);
    assert_eq!(ts.second(), 45);
}

#[test]
fn timestamp_roundtrip() {
    let date = time::Date::from_calendar_date(2024, time::Month::January, 15).unwrap();
    let time = time::Time::from_hms_micro(10, 30, 45, 123456).unwrap();
    let original = time::PrimitiveDateTime::new(date, time);
    let mut buf = Vec::new();
    original
        .encode(time::PrimitiveDateTime::NATURAL_OID, &mut buf)
        .unwrap();
    let decoded = time::PrimitiveDateTime::from_binary(oid::TIMESTAMP, &buf[4..]).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn timestamptz_binary() {
    // Same as timestamp but with timezone
    let day_usecs: i64 = 8780 * 24 * 3600 * 1_000_000;
    let time_usecs: i64 = (10 * 3600 + 30 * 60 + 45) * 1_000_000;
    let total_usecs = day_usecs + time_usecs;
    let bytes = total_usecs.to_be_bytes();
    let ts = time::OffsetDateTime::from_binary(oid::TIMESTAMPTZ, &bytes).unwrap();
    assert_eq!(ts.year(), 2024);
    assert_eq!(ts.month() as u8, 1);
    assert_eq!(ts.day(), 15);
    assert_eq!(ts.hour(), 10);
    assert_eq!(ts.minute(), 30);
    assert_eq!(ts.second(), 45);
}

#[test]
fn timestamptz_roundtrip() {
    let original = time::OffsetDateTime::now_utc();
    // Truncate to microseconds (PostgreSQL precision)
    let original = original
        .replace_nanosecond((original.nanosecond() / 1000) * 1000)
        .unwrap();
    let mut buf = Vec::new();
    original
        .encode(time::OffsetDateTime::NATURAL_OID, &mut buf)
        .unwrap();
    let decoded = time::OffsetDateTime::from_binary(oid::TIMESTAMPTZ, &buf[4..]).unwrap();
    assert_eq!(original, decoded);
}

fn interval_bytes(months: i32, days: i32, microseconds: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    Interval {
        months,
        days,
        microseconds,
    }
    .encode(oid::INTERVAL, &mut buf)
    .unwrap();
    buf.split_off(4)
}

#[test]
fn signed_duration_text_unsupported() {
    let message = time::SignedDuration::from_text(oid::INTERVAL, b"04:05:06")
        .unwrap_err()
        .to_string();
    assert!(message.contains(INTERVAL_TEXT_UNSUPPORTED), "{message}");
    time::SignedDuration::from_text(oid::TIME, b"04:05:06").unwrap_err();
}

#[test]
fn signed_duration_binary() {
    assert_eq!(
        time::SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(0, 0, -1)).unwrap(),
        time::SignedDuration::microseconds(-1)
    );
    assert_eq!(
        time::SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(0, 0, i64::MAX)).unwrap(),
        time::SignedDuration::microseconds(i64::MAX)
    );
    time::SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(-1, 0, 0)).unwrap_err();
    time::SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(0, 2, -1)).unwrap_err();
    time::SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(i32::MAX, i32::MAX, i64::MAX))
        .unwrap_err();
    time::SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(i32::MIN, i32::MIN, i64::MIN))
        .unwrap_err();
    time::SignedDuration::from_binary(oid::INTERVAL, &[0; 8]).unwrap_err();
    time::SignedDuration::from_binary(oid::TIME, &interval_bytes(0, 0, 1)).unwrap_err();
    let message = time::SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(0, 1, 0))
        .unwrap_err()
        .to_string();
    assert!(message.contains("decode as Interval"), "{message}");
}

#[test]
fn signed_duration_roundtrip() {
    for original in [
        time::SignedDuration::ZERO,
        time::SignedDuration::new(100 * 86_400 + 5, 123_456_000),
        time::SignedDuration::new(-100 * 86_400 - 5, -123_456_000),
        time::SignedDuration::microseconds(i64::MAX),
        time::SignedDuration::microseconds(i64::MIN),
    ] {
        let mut buf = Vec::new();
        original
            .encode(time::SignedDuration::NATURAL_OID, &mut buf)
            .unwrap();
        assert_eq!(buf.len(), 20);
        assert_eq!(buf[12..], [0; 8]);
        assert_eq!(
            time::SignedDuration::from_binary(oid::INTERVAL, &buf[4..]).unwrap(),
            original
        );
    }
}

#[test]
fn signed_duration_encode_errors() {
    let mut buf = Vec::new();
    time::SignedDuration::nanoseconds(1)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    time::SignedDuration::nanoseconds(-1_001)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    time::SignedDuration::MAX
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    time::SignedDuration::MIN
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    (time::SignedDuration::microseconds(i64::MAX) + time::SignedDuration::MICROSECOND)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    time::SignedDuration::SECOND
        .encode(oid::INT8, &mut buf)
        .unwrap_err();
}

#[test]
fn encode_sub_microsecond_errors() {
    use time::macros::{datetime, time};

    let mut buf = Vec::new();

    time!(10:30:45.123456789)
        .encode(oid::TIME, &mut buf)
        .unwrap_err();
    time!(10:30:45.123456).encode(oid::TIME, &mut buf).unwrap();

    datetime!(2024-01-15 10:30:45.000000001)
        .encode(oid::TIMESTAMP, &mut buf)
        .unwrap_err();
    datetime!(2024-01-15 10:30:45.000000001)
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap_err();
    datetime!(2024-01-15 10:30:45.000001)
        .encode(oid::TIMESTAMP, &mut buf)
        .unwrap();

    datetime!(2024-01-15 10:30:45.000000999 +09:00)
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap_err();
    datetime!(1950-01-15 10:30:45.000000999 UTC)
        .encode(oid::TIMESTAMP, &mut buf)
        .unwrap_err();
    datetime!(1950-01-15 10:30:45.000001 UTC)
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap();
}
