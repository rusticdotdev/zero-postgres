use super::*;

const SERVER_INTERVALS: [(&str, u128); 20] = [
    (
        "1 year 2 mons 3 days 04:05:06.789",
        0x000000036c97ca88000000030000000e,
    ),
    ("-1 days +02:03:04", 0x00000001b81ee600ffffffff00000000),
    ("00:00:00", 0),
    ("1 day", 0x00000000000000000000000100000000),
    ("1 mon", 0x00000000000000000000000000000001),
    (
        "-1 years -2 mons +3 days -04:05:06.000001",
        0xfffffffc93743f7f00000003fffffff2,
    ),
    ("1 mon -1 days", 0x0000000000000000ffffffff00000001),
    ("-00:00:00.5", 0xfffffffffff85ee00000000000000000),
    (
        "2562047788:00:54.775807",
        0x7fffffffffffffff0000000000000000,
    ),
    (
        "-2562047788:00:54.775808",
        0x80000000000000000000000000000000,
    ),
    ("100:00:00", 0x00000053d1ac10000000000000000000),
    ("1 year 1 mon", 0x0000000000000000000000000000000d),
    (
        "-1 mons +1 day 00:00:01",
        0x00000000000f424000000001ffffffff,
    ),
    ("1 year", 0x0000000000000000000000000000000c),
    ("2 years -1 days", 0x0000000000000000ffffffff00000018),
    ("00:00:00.1", 0x00000000000186a00000000000000000),
    (
        "178956970 years 7 mons 2147483647 days 2562047788:00:54.775806",
        0x7ffffffffffffffe7fffffff7fffffff,
    ),
    ("1 day 12:00:00", 0x0000000a0eebb0000000000100000000),
    ("1 day -00:00:01", 0xfffffffffff0bdc00000000100000000),
    (
        "-178956970 years -8 mons -2147483648 days",
        0x00000000000000008000000080000000,
    ),
];

const SERVER_TIMESTAMPS: [(&str, u64); 14] = [
    ("2024-01-15 19:30:45+09", 0x0002b1f8466d5f40),
    ("2024-01-15 16:00:45+05:30", 0x0002b1f8466d5f40),
    ("2024-01-15 05:30:45-05", 0x0002b1f8466d5f40),
    ("2024-01-15 19:30:45.123456+09", 0x0002b1f8466f4180),
    ("2024-01-15 19:30:45.1+09", 0x0002b1f8466ee5e0),
    ("1969-07-21 05:17:40+09", 0xfffc96188bae6100),
    ("0001-01-01 08:27:52+08:27:52", 0xff1fe2ffc59c6000),
    ("0044-03-15 20:27:52+08:27:52 BC", 0xff1af9e8fb46d000),
    ("0044-03-15 07:03:58-04:56:02 BC", 0xff1af9e8fb46d000),
    ("4713-11-24 08:27:52+08:27:52 BC", 0xfd0f9983eb0ae000),
    ("294277-01-01 08:59:59.999999+09", 0x7fffff5bb3b29fff),
    ("10000-01-01 09:00:00+09", 0x0380e70b913b8000),
    ("2000-03-01 08:59:59+09", 0x000004b6fe6b3dc0),
    ("1900-01-01 08:27:52+08:27:52", 0xfff4c9ee7c0b8000),
];

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
fn interval_text_unsupported() {
    for text in ["00:00:00", "1 year 2 mons 3 days 04:05:06.789", "infinity"] {
        let message = Interval::from_text(oid::INTERVAL, text.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(message.contains(INTERVAL_TEXT_UNSUPPORTED), "{message}");
    }
}

#[test]
fn duration_text_unsupported() {
    let message = Duration::from_text(oid::INTERVAL, b"04:05:06")
        .unwrap_err()
        .to_string();
    assert!(message.contains(INTERVAL_TEXT_UNSUPPORTED), "{message}");
}

#[test]
fn interval_binary() {
    assert_eq!(
        Interval::from_binary(
            oid::INTERVAL,
            &0x000000036c97ca88000000030000000e_u128.to_be_bytes()
        )
        .unwrap(),
        Interval {
            months: 14,
            days: 3,
            microseconds: 14_706_789_000,
        }
    );
    assert_eq!(
        Interval::from_binary(
            oid::INTERVAL,
            &0x00000001b81ee600ffffffff00000000_u128.to_be_bytes()
        )
        .unwrap(),
        Interval {
            months: 0,
            days: -1,
            microseconds: 7_384_000_000,
        }
    );
}

#[test]
fn interval_infinity() {
    let infinity = Interval {
        months: i32::MAX,
        days: i32::MAX,
        microseconds: i64::MAX,
    };
    let neg_infinity = Interval {
        months: i32::MIN,
        days: i32::MIN,
        microseconds: i64::MIN,
    };
    let infinity_bytes = 0x7fffffffffffffff7fffffff7fffffff_u128.to_be_bytes();
    let neg_infinity_bytes = 0x80000000000000008000000080000000_u128.to_be_bytes();

    assert_eq!(
        Interval::from_binary(oid::INTERVAL, &infinity_bytes).unwrap(),
        infinity
    );
    assert_eq!(
        Interval::from_binary(oid::INTERVAL, &neg_infinity_bytes).unwrap(),
        neg_infinity
    );

    let mut buf = Vec::new();
    infinity.encode(oid::INTERVAL, &mut buf).unwrap();
    assert_eq!(buf[4..], infinity_bytes);
    buf.clear();
    neg_infinity.encode(oid::INTERVAL, &mut buf).unwrap();
    assert_eq!(buf[4..], neg_infinity_bytes);
}

#[test]
fn interval_binary_invalid_length() {
    Interval::from_binary(oid::INTERVAL, &[0; 15]).unwrap_err();
    Interval::from_binary(oid::INTERVAL, &[0; 17]).unwrap_err();
    Interval::from_binary(oid::INTERVAL, &[]).unwrap_err();
}

#[test]
fn interval_encode() {
    assert_eq!(Interval::NATURAL_OID, oid::INTERVAL);
    let mut buf = Vec::new();
    Interval {
        months: 14,
        days: 3,
        microseconds: 14_706_789_000,
    }
    .encode(oid::INTERVAL, &mut buf)
    .unwrap();
    assert_eq!(buf[..4], 16_i32.to_be_bytes());
    assert_eq!(
        buf[4..],
        0x000000036c97ca88000000030000000e_u128.to_be_bytes()
    );
}

#[test]
fn interval_roundtrip() {
    for (text, binary) in SERVER_INTERVALS {
        let bytes = binary.to_be_bytes();
        let mut buf = Vec::new();
        Interval::from_binary(oid::INTERVAL, &bytes)
            .unwrap()
            .encode(oid::INTERVAL, &mut buf)
            .unwrap();
        assert_eq!(buf[4..], bytes, "{text}");
    }
    for original in [
        Interval {
            months: -1,
            days: 2,
            microseconds: -3,
        },
        Interval {
            months: i32::MAX,
            days: i32::MIN,
            microseconds: i64::MAX,
        },
        Interval {
            months: i32::MAX,
            days: i32::MAX,
            microseconds: i64::MAX,
        },
        Interval {
            months: i32::MIN,
            days: i32::MIN,
            microseconds: i64::MIN,
        },
    ] {
        let mut buf = Vec::new();
        original.encode(oid::INTERVAL, &mut buf).unwrap();
        assert_eq!(
            Interval::from_binary(oid::INTERVAL, &buf[4..]).unwrap(),
            original
        );
    }
}

#[test]
fn interval_wrong_oid() {
    Interval::from_text(oid::TIME, b"04:05:06").unwrap_err();
    Interval::from_text(oid::TEXT, b"infinity").unwrap_err();
    Interval::from_binary(oid::INT8, &[0; 16]).unwrap_err();
    Interval::from_binary(oid::TIMESTAMPTZ, &[0; 16]).unwrap_err();
    let mut buf = Vec::new();
    Interval::default().encode(oid::TIME, &mut buf).unwrap_err();
    Interval::default().encode(oid::TEXT, &mut buf).unwrap_err();
    assert!(buf.is_empty());
}

#[test]
fn duration_binary() {
    assert_eq!(
        Duration::from_binary(oid::INTERVAL, &interval_bytes(0, 0, 14_706_789_000)).unwrap(),
        Duration::from_micros(14_706_789_000)
    );
    assert_eq!(
        Duration::from_binary(oid::INTERVAL, &interval_bytes(0, 0, i64::MAX)).unwrap(),
        Duration::from_micros(i64::MAX as u64)
    );
}

#[test]
fn duration_months_or_days() {
    Duration::from_binary(oid::INTERVAL, &interval_bytes(1, 0, 0)).unwrap_err();
    Duration::from_binary(oid::INTERVAL, &interval_bytes(0, 2, 1)).unwrap_err();
    let message = Duration::from_binary(oid::INTERVAL, &interval_bytes(0, 1, 0))
        .unwrap_err()
        .to_string();
    assert!(message.contains("decode as Interval"), "{message}");
}

#[test]
fn duration_negative() {
    Duration::from_binary(oid::INTERVAL, &interval_bytes(0, -1, 0)).unwrap_err();
    let message = Duration::from_binary(oid::INTERVAL, &interval_bytes(0, 0, -1))
        .unwrap_err()
        .to_string();
    assert!(message.contains("decode as Interval"), "{message}");
}

#[test]
fn duration_infinity() {
    Duration::from_binary(oid::INTERVAL, &interval_bytes(i32::MIN, i32::MIN, i64::MIN))
        .unwrap_err();
    Duration::from_binary(oid::INTERVAL, &interval_bytes(i32::MAX, i32::MAX, i64::MAX))
        .unwrap_err();
}

#[test]
fn duration_wrong_oid() {
    Duration::from_text(oid::INT8, b"00:00:01").unwrap_err();
    Duration::from_binary(oid::TIME, &interval_bytes(0, 0, 1)).unwrap_err();
    Duration::from_secs(1)
        .encode(oid::INT8, &mut Vec::new())
        .unwrap_err();
}

#[test]
fn duration_roundtrip() {
    for original in [
        Duration::ZERO,
        Duration::from_micros(1),
        Duration::new(100 * 86_400 + 5, 123_456_000),
        Duration::from_micros(i64::MAX as u64),
    ] {
        let mut buf = Vec::new();
        original.encode(Duration::NATURAL_OID, &mut buf).unwrap();
        assert_eq!(buf.len(), 20);
        assert_eq!(buf[12..], [0; 8]);
        assert_eq!(
            Duration::from_binary(oid::INTERVAL, &buf[4..]).unwrap(),
            original
        );
    }
}

#[test]
fn duration_encode_sub_microsecond() {
    let mut buf = Vec::new();
    Duration::from_nanos(1)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    Duration::new(1, 999)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
}

#[test]
fn duration_encode_overflow() {
    let mut buf = Vec::new();
    Duration::from_micros(i64::MAX as u64 + 1)
        .encode(oid::INTERVAL, &mut buf)
        .unwrap_err();
    Duration::MAX.encode(oid::INTERVAL, &mut buf).unwrap_err();
}

#[test]
fn system_time_text_matches_binary() {
    for (text, binary) in SERVER_TIMESTAMPS {
        assert_eq!(
            SystemTime::from_text(oid::TIMESTAMPTZ, text.as_bytes()).unwrap(),
            SystemTime::from_binary(oid::TIMESTAMPTZ, &binary.to_be_bytes()).unwrap(),
            "{text}"
        );
    }
}

#[test]
fn system_time_text() {
    let expected = UNIX_EPOCH + Duration::from_secs(1_705_314_645);
    for text in [
        "2024-01-15 10:30:45+00",
        "2024-01-15 19:30:45+09",
        "2024-01-15 16:00:45+05:30",
        "2024-01-15 05:30:45-05",
    ] {
        assert_eq!(
            SystemTime::from_text(oid::TIMESTAMPTZ, text.as_bytes()).unwrap(),
            expected,
            "{text}"
        );
    }
    assert_eq!(
        SystemTime::from_text(oid::TIMESTAMPTZ, b"2024-01-15 10:30:45.123456+00").unwrap(),
        expected + Duration::from_micros(123_456)
    );
    assert_eq!(
        SystemTime::from_text(oid::TIMESTAMPTZ, b"1970-01-01 00:00:00+00").unwrap(),
        UNIX_EPOCH
    );
    assert_eq!(
        SystemTime::from_text(oid::TIMESTAMPTZ, b"1969-12-31 23:59:59.999999+00").unwrap(),
        UNIX_EPOCH - Duration::from_micros(1)
    );
    assert_eq!(
        SystemTime::from_text(oid::TIMESTAMPTZ, b"1799-12-31 19:03:58-04:56:02").unwrap(),
        SystemTime::from_text(oid::TIMESTAMPTZ, b"1800-01-01 00:00:00+00").unwrap()
    );
}

#[test]
fn system_time_text_invalid() {
    for text in [
        "",
        "2024-01-15",
        "2024-01-15 10:30:45",
        "2024-01-15T10:30:45+00",
        "2024-01-15 10:30:45 +00",
        "2024-01-15 10:30:45Z",
        "2024-01-15 10:30:45+0",
        "2024-01-15 10:30:45+00:",
        "2024-01-15 10:30:45+00:00:00:00",
        "2024-01-15 10:30:45+00:60",
        "2024-01-15 10:30:45.+00",
        "2024-01-15 10:30:45.1234567+00",
        "2024-01-15 24:00:00+00",
        "2024-01-15 1:30:45+00",
        "2024-01-15 10:60:45+00",
        "2024-01-15 10:30:60+00",
        "2024-13-15 10:30:45+00",
        "2024-00-15 10:30:45+00",
        "2024-01-00 10:30:45+00",
        "2024-01-32 10:30:45+00",
        "2023-02-29 10:30:45+00",
        "1900-02-29 10:30:45+00",
        "0000-01-01 00:00:00+00",
        "024-01-15 10:30:45+00",
        "-2024-01-15 10:30:45+00",
        "2024-01-15 10:30:45+00 AD",
        "01/15/2024 19:30:45 KST",
        "15.01.2024 19:30:45 KST",
        "Mon 15 Jan 19:30:45 2024 KST",
    ] {
        SystemTime::from_text(oid::TIMESTAMPTZ, text.as_bytes()).unwrap_err();
    }
    SystemTime::from_text(oid::TIMESTAMPTZ, b"2000-02-29 10:30:45+00").unwrap();
    SystemTime::from_text(oid::TIMESTAMPTZ, b"2024-02-29 10:30:45+00").unwrap();
}

#[test]
fn system_time_binary() {
    assert_eq!(
        SystemTime::from_binary(oid::TIMESTAMPTZ, &0_i64.to_be_bytes()).unwrap(),
        UNIX_EPOCH + Duration::from_secs(946_684_800)
    );
    assert_eq!(
        SystemTime::from_binary(oid::TIMESTAMPTZ, &(-1_i64).to_be_bytes()).unwrap(),
        UNIX_EPOCH + Duration::new(946_684_799, 999_999_000)
    );
    assert_eq!(
        SystemTime::from_binary(oid::TIMESTAMPTZ, &(-946_684_800_000_001_i64).to_be_bytes())
            .unwrap(),
        UNIX_EPOCH - Duration::from_micros(1)
    );
    SystemTime::from_binary(oid::TIMESTAMPTZ, &[0; 4]).unwrap_err();
}

#[test]
fn system_time_infinity() {
    SystemTime::from_text(oid::TIMESTAMPTZ, b"infinity").unwrap_err();
    SystemTime::from_text(oid::TIMESTAMPTZ, b"-infinity").unwrap_err();
    SystemTime::from_binary(oid::TIMESTAMPTZ, &i64::MAX.to_be_bytes()).unwrap_err();
    SystemTime::from_binary(oid::TIMESTAMPTZ, &i64::MIN.to_be_bytes()).unwrap_err();
}

#[test]
fn system_time_wrong_oid() {
    SystemTime::from_text(oid::TIMESTAMP, b"2024-01-15 10:30:45+00").unwrap_err();
    SystemTime::from_binary(oid::TIMESTAMP, &0_i64.to_be_bytes()).unwrap_err();
    UNIX_EPOCH
        .encode(oid::TIMESTAMP, &mut Vec::new())
        .unwrap_err();
}

#[test]
fn system_time_roundtrip() {
    for original in [
        UNIX_EPOCH,
        UNIX_EPOCH + Duration::new(1_705_314_645, 123_456_000),
        UNIX_EPOCH - Duration::new(14_182_940, 1_000),
        UNIX_EPOCH - Duration::from_secs(62_135_596_800),
    ] {
        let mut buf = Vec::new();
        original.encode(SystemTime::NATURAL_OID, &mut buf).unwrap();
        assert_eq!(buf[..4], 8_i32.to_be_bytes());
        assert_eq!(
            SystemTime::from_binary(oid::TIMESTAMPTZ, &buf[4..]).unwrap(),
            original
        );
    }
    let mut buf = Vec::new();
    (UNIX_EPOCH + Duration::from_secs(1_705_314_645))
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap();
    assert_eq!(buf[4..], 0x0002b1f8466d5f40_u64.to_be_bytes());
}

#[test]
fn system_time_encode_sub_microsecond() {
    let mut buf = Vec::new();
    (UNIX_EPOCH + Duration::from_nanos(1))
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap_err();
    (UNIX_EPOCH - Duration::from_nanos(1_001))
        .encode(oid::TIMESTAMPTZ, &mut buf)
        .unwrap_err();
}

#[test]
fn system_time_encode_out_of_range() {
    let mut buf = Vec::new();
    for distance in [
        Duration::from_micros(i64::MAX as u64) + Duration::from_secs(946_684_800),
        Duration::from_secs(1 << 60),
    ] {
        if let Some(system_time) = UNIX_EPOCH.checked_add(distance) {
            system_time.encode(oid::TIMESTAMPTZ, &mut buf).unwrap_err();
        }
        if let Some(system_time) = UNIX_EPOCH.checked_sub(distance) {
            system_time.encode(oid::TIMESTAMPTZ, &mut buf).unwrap_err();
        }
    }
}
