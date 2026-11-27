use super::*;
use jiff::civil::{date, time};

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
    original.encode(Date::NATURAL_OID, &mut buf).unwrap();
    let decoded = Date::from_binary(oid::DATE, &buf[4..]).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn date_roundtrip_before_epoch() {
    let original = date(1900, 1, 1);
    let mut buf = Vec::new();
    original.encode(Date::NATURAL_OID, &mut buf).unwrap();
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
    original.encode(Time::NATURAL_OID, &mut buf).unwrap();
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
            .to_zoned_datetime(TimeZone::UTC)
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
    original.encode(DateTime::NATURAL_OID, &mut buf).unwrap();
    let decoded = DateTime::from_binary(oid::TIMESTAMP, &buf[4..]).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn timestamp_roundtrip_before_epoch() {
    let original = date(1969, 7, 20).at(20, 17, 40, 123_456_000);
    let mut buf = Vec::new();
    original.encode(DateTime::NATURAL_OID, &mut buf).unwrap();
    let decoded = DateTime::from_binary(oid::TIMESTAMP, &buf[4..]).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn timestamptz_text() {
    let expected = date(2024, 1, 15)
        .at(10, 30, 45, 0)
        .to_zoned_datetime(TimeZone::UTC)
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
        .to_zoned_datetime(TimeZone::UTC);
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
    original.encode(Timestamp::NATURAL_OID, &mut buf).unwrap();
    let decoded = Timestamp::from_binary(oid::TIMESTAMPTZ, &buf[4..]).unwrap();
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
fn zoned_text() {
    let expected = date(2024, 1, 15)
        .at(10, 30, 45, 123_456_000)
        .to_zoned_datetime(TimeZone::UTC)
        .unwrap();
    let decoded =
        ZonedDateTime::from_text(oid::TIMESTAMPTZ, b"2024-01-15 19:30:45.123456+09").unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(decoded.time_zone(), &TimeZone::UTC);
    assert_eq!(decoded.hour(), 10);
    ZonedDateTime::from_text(oid::TIMESTAMPTZ, b"infinity").unwrap_err();
    ZonedDateTime::from_text(oid::TIMESTAMP, b"2024-01-15 19:30:45+09").unwrap_err();
}

#[test]
fn zoned_binary() {
    let decoded =
        ZonedDateTime::from_binary(oid::TIMESTAMPTZ, &0x0002b1f8466f4180_u64.to_be_bytes())
            .unwrap();
    assert_eq!(
        decoded,
        date(2024, 1, 15)
            .at(10, 30, 45, 123_456_000)
            .to_zoned_datetime(TimeZone::UTC)
            .unwrap()
    );
    assert_eq!(decoded.time_zone(), &TimeZone::UTC);
    ZonedDateTime::from_binary(oid::TIMESTAMPTZ, &i64::MAX.to_be_bytes()).unwrap_err();
    ZonedDateTime::from_binary(oid::TIMESTAMPTZ, &i64::MIN.to_be_bytes()).unwrap_err();
    ZonedDateTime::from_binary(oid::TIMESTAMP, &0_i64.to_be_bytes()).unwrap_err();
}

#[test]
fn zoned_roundtrip() {
    for original in [
        date(2024, 1, 15).at(10, 30, 45, 123_456_000),
        date(1969, 7, 20).at(20, 17, 40, 1_000),
    ] {
        let original = original.to_zoned_datetime(TimeZone::UTC).unwrap();
        let mut buf = Vec::new();
        original
            .encode(ZonedDateTime::NATURAL_OID, &mut buf)
            .unwrap();
        assert_eq!(buf[..4], 8_i32.to_be_bytes());
        assert_eq!(
            ZonedDateTime::from_binary(oid::TIMESTAMPTZ, &buf[4..]).unwrap(),
            original
        );
    }
}

#[test]
fn zoned_encode_fixed_offset() {
    let zoned = date(2024, 1, 15)
        .at(19, 30, 45, 0)
        .to_zoned_datetime(TimeZone::fixed(jiff::tz::offset(9)))
        .unwrap();
    let mut buf = Vec::new();
    zoned.encode(oid::TIMESTAMPTZ, &mut buf).unwrap();
    assert_eq!(buf[4..], 0x0002b1f8466d5f40_u64.to_be_bytes());
}

#[test]
fn zoned_encode_errors() {
    let mut buf = Vec::new();
    date(2024, 1, 15)
        .at(10, 30, 45, 1)
        .to_zoned_datetime(TimeZone::UTC)
        .unwrap()
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap_err();
    date(2024, 1, 15)
        .at(10, 30, 45, 0)
        .to_zoned_datetime(TimeZone::UTC)
        .unwrap()
        .encode(oid::TIMESTAMP, &mut buf)
        .unwrap_err();
}

#[test]
fn span_text_unsupported() {
    let message = Span::from_text(oid::INTERVAL, b"04:05:06")
        .unwrap_err()
        .to_string();
    assert!(message.contains(INTERVAL_TEXT_UNSUPPORTED), "{message}");
    Span::from_text(oid::TIME, b"04:05:06").unwrap_err();
}

#[test]
fn span_binary() {
    assert_eq!(
        Span::from_binary(
            oid::INTERVAL,
            &0x000000036c97ca88000000030000000e_u128.to_be_bytes()
        )
        .unwrap()
        .fieldwise(),
        Span::new()
            .months(14)
            .days(3)
            .microseconds(14_706_789_000_i64)
            .fieldwise()
    );
    Span::from_binary(oid::INTERVAL, &[0; 8]).unwrap_err();
    Span::from_binary(oid::TIME, &interval_bytes(0, 0, 1)).unwrap_err();
    Span::from_binary(oid::INTERVAL, &interval_bytes(i32::MAX, i32::MAX, i64::MAX)).unwrap_err();
    Span::from_binary(oid::INTERVAL, &interval_bytes(i32::MIN, i32::MIN, i64::MIN)).unwrap_err();
}

#[test]
fn span_mixed_signs() {
    let message = Span::from_binary(oid::INTERVAL, &interval_bytes(-1, 0, 1))
        .unwrap_err()
        .to_string();
    assert!(message.contains("decode as Interval"), "{message}");
    Span::from_binary(oid::INTERVAL, &interval_bytes(0, -1, -1)).unwrap();
}

#[test]
fn span_out_of_range() {
    Span::from_binary(oid::INTERVAL, &interval_bytes(i32::MAX, 0, 0)).unwrap_err();
    Span::from_binary(oid::INTERVAL, &interval_bytes(0, i32::MAX, 0)).unwrap_err();
    Span::from_binary(oid::INTERVAL, &interval_bytes(0, 0, i64::MAX)).unwrap_err();
    let message = Span::from_binary(oid::INTERVAL, &interval_bytes(i32::MAX, i32::MAX, i64::MAX))
        .unwrap_err()
        .to_string();
    assert!(message.contains("decode as Interval"), "{message}");
}

#[test]
fn span_encode() {
    let mut buf = Vec::new();
    Span::new()
        .years(1)
        .months(2)
        .weeks(1)
        .days(3)
        .hours(4)
        .minutes(5)
        .seconds(6)
        .milliseconds(789)
        .microseconds(10)
        .nanoseconds(2_000)
        .encode(Span::NATURAL_OID, &mut buf)
        .unwrap();
    assert_eq!(buf[..4], 16_i32.to_be_bytes());
    assert_eq!(buf[4..], interval_bytes(14, 10, 14_706_789_012));

    buf.clear();
    Span::new()
        .months(-1)
        .days(-2)
        .seconds(-3)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap();
    assert_eq!(buf[4..], interval_bytes(-1, -2, -3_000_000));
}

#[test]
fn span_roundtrip() {
    let original = Span::new()
        .months(14)
        .days(3)
        .microseconds(14_706_789_000_i64);
    let mut buf = Vec::new();
    original.encode(oid::INTERVAL, &mut buf).unwrap();
    assert_eq!(
        Span::from_binary(oid::INTERVAL, &buf[4..])
            .unwrap()
            .fieldwise(),
        original.fieldwise()
    );
}

#[test]
fn span_encode_errors() {
    let mut buf = Vec::new();
    Span::new()
        .nanoseconds(1)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    Span::new()
        .microseconds(1)
        .nanoseconds(1_500)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    Span::new().days(1).encode(oid::INT8, &mut buf).unwrap_err();
}

#[test]
fn signed_duration_text_unsupported() {
    let message = SignedDuration::from_text(oid::INTERVAL, b"04:05:06")
        .unwrap_err()
        .to_string();
    assert!(message.contains(INTERVAL_TEXT_UNSUPPORTED), "{message}");
    SignedDuration::from_text(oid::TIME, b"04:05:06").unwrap_err();
}

#[test]
fn signed_duration_binary() {
    assert_eq!(
        SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(0, 0, -1)).unwrap(),
        SignedDuration::from_micros(-1)
    );
    assert_eq!(
        SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(0, 0, i64::MAX)).unwrap(),
        SignedDuration::from_micros(i64::MAX)
    );
    SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(-1, 0, 0)).unwrap_err();
    SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(0, 2, -1)).unwrap_err();
    SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(i32::MAX, i32::MAX, i64::MAX))
        .unwrap_err();
    SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(i32::MIN, i32::MIN, i64::MIN))
        .unwrap_err();
    SignedDuration::from_binary(oid::INTERVAL, &[0; 8]).unwrap_err();
    SignedDuration::from_binary(oid::TIME, &interval_bytes(0, 0, 1)).unwrap_err();
    let message = SignedDuration::from_binary(oid::INTERVAL, &interval_bytes(0, 1, 0))
        .unwrap_err()
        .to_string();
    assert!(message.contains("decode as Interval"), "{message}");
}

#[test]
fn signed_duration_roundtrip() {
    for original in [
        SignedDuration::ZERO,
        SignedDuration::new(100 * 86_400 + 5, 123_456_000),
        SignedDuration::new(-100 * 86_400 - 5, -123_456_000),
        SignedDuration::from_micros(i64::MAX),
        SignedDuration::from_micros(i64::MIN),
    ] {
        let mut buf = Vec::new();
        original
            .encode(SignedDuration::NATURAL_OID, &mut buf)
            .unwrap();
        assert_eq!(buf.len(), 20);
        assert_eq!(buf[12..], [0; 8]);
        assert_eq!(
            SignedDuration::from_binary(oid::INTERVAL, &buf[4..]).unwrap(),
            original
        );
    }
}

#[test]
fn signed_duration_encode_errors() {
    let mut buf = Vec::new();
    SignedDuration::from_nanos(1)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    SignedDuration::from_nanos(-1_001)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    SignedDuration::MAX
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    SignedDuration::MIN
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    (SignedDuration::from_micros(i64::MAX) + SignedDuration::from_micros(1))
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    SignedDuration::from_secs(1)
        .encode(oid::INT8, &mut buf)
        .unwrap_err();
}

#[test]
fn encode_sub_microsecond_errors() {
    let mut buf = Vec::new();

    time(10, 30, 45, 123_456_789)
        .encode(oid::TIME, &mut buf)
        .unwrap_err();
    time(10, 30, 45, 123_456_000)
        .encode(oid::TIME, &mut buf)
        .unwrap();

    date(2024, 1, 15)
        .at(10, 30, 45, 1)
        .encode(oid::TIMESTAMP, &mut buf)
        .unwrap_err();
    date(2024, 1, 15)
        .at(10, 30, 45, 1)
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap_err();
    date(2024, 1, 15)
        .at(10, 30, 45, 1_000)
        .encode(oid::TIMESTAMP, &mut buf)
        .unwrap();

    Timestamp::new(1_700_000_000, 1)
        .unwrap()
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap_err();
    Timestamp::new(-1_700_000_000, -999)
        .unwrap()
        .encode(oid::TIMESTAMP, &mut buf)
        .unwrap_err();
    Timestamp::new(-1_700_000_000, -1_000)
        .unwrap()
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap();
}
