use std::time::SystemTime;

use super::*;

fn encoded<V: ToWireValue>(value: V, target_oid: Oid) -> Vec<u8> {
    let mut buf = Vec::new();
    value.encode(target_oid, &mut buf).unwrap();
    buf
}

fn int4(value: i32) -> [u8; 8] {
    let mut bytes = [0, 0, 0, 4, 0, 0, 0, 0];
    bytes[4..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn int8(value: i64) -> [u8; 12] {
    let mut bytes = [0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0];
    bytes[4..].copy_from_slice(&value.to_be_bytes());
    bytes
}

#[test]
fn range_encode() {
    let buf = encoded(1_i32..5, oid::INT4RANGE);
    assert_eq!(buf[..4], 17_i32.to_be_bytes());
    assert_eq!(buf[4], FLAG_LOWER_INCLUDED);
    assert_eq!(buf[5..13], int4(1));
    assert_eq!(buf[13..], int4(5));
}

#[test]
fn range_inclusive_encode() {
    let buf = encoded(1_i32..=5, oid::INT4RANGE);
    assert_eq!(buf[..4], 17_i32.to_be_bytes());
    assert_eq!(buf[4], FLAG_LOWER_INCLUDED | FLAG_UPPER_INCLUDED);
    assert_eq!(buf[5..13], int4(1));
    assert_eq!(buf[13..], int4(5));
}

#[test]
fn range_from_encode() {
    let buf = encoded(1_i32.., oid::INT4RANGE);
    assert_eq!(buf[..4], 9_i32.to_be_bytes());
    assert_eq!(buf[4], FLAG_LOWER_INCLUDED | FLAG_UPPER_UNBOUNDED);
    assert_eq!(buf[5..], int4(1));
}

#[test]
fn range_to_encode() {
    let buf = encoded(..5_i32, oid::INT4RANGE);
    assert_eq!(buf[..4], 9_i32.to_be_bytes());
    assert_eq!(buf[4], FLAG_LOWER_UNBOUNDED);
    assert_eq!(buf[5..], int4(5));
}

#[test]
fn range_to_inclusive_encode() {
    let buf = encoded(..=5_i32, oid::INT4RANGE);
    assert_eq!(buf[..4], 9_i32.to_be_bytes());
    assert_eq!(buf[4], FLAG_LOWER_UNBOUNDED | FLAG_UPPER_INCLUDED);
    assert_eq!(buf[5..], int4(5));
}

#[test]
fn range_encode_widens_elements() {
    let buf = encoded(1_i32..5, oid::INT8RANGE);
    assert_eq!(buf[..4], 25_i32.to_be_bytes());
    assert_eq!(buf[4], FLAG_LOWER_INCLUDED);
    assert_eq!(buf[5..17], int8(1));
    assert_eq!(buf[17..], int8(5));
}

#[test]
fn range_encode_equal_bounds() {
    let buf = encoded(5_i32..5, oid::INT4RANGE);
    assert_eq!(buf[4], FLAG_LOWER_INCLUDED);
    assert_eq!(buf[5..13], int4(5));
    assert_eq!(buf[13..], int4(5));

    let inclusive = encoded(5_i32..=5, oid::INT4RANGE);
    assert_eq!(inclusive[4], FLAG_LOWER_INCLUDED | FLAG_UPPER_INCLUDED);
}

#[test]
fn range_encode_reversed_bounds() {
    let mut buf = Vec::new();
    let (start, end) = (5_i32, 1);
    (start..end).encode(oid::INT4RANGE, &mut buf).unwrap_err();
    (start..=end).encode(oid::INT4RANGE, &mut buf).unwrap_err();
    assert!(buf.is_empty());
}

#[test]
fn range_inclusive_encode_exhausted_by_iteration() {
    let mut range = 1_i32..=3;
    range.by_ref().for_each(drop);
    let buf = encoded(range, oid::INT4RANGE);
    assert_eq!(buf[..4], 1_i32.to_be_bytes());
    assert_eq!(buf[4..], [FLAG_EMPTY]);
}

#[test]
fn range_encode_oid_mismatch() {
    let mut buf = Vec::new();
    (1_i32..5).encode(oid::INT4, &mut buf).unwrap_err();
    (1_i32..5).encode(oid::NUMRANGE, &mut buf).unwrap_err();
    (1_i32..5).encode(oid::DATERANGE, &mut buf).unwrap_err();
    (1_i32..=5).encode(oid::INT4, &mut buf).unwrap_err();
    assert!(buf.is_empty());
}

#[test]
fn range_encode_element_overflow() {
    let mut buf = vec![0xAA];
    (1_i64..i64::MAX)
        .encode(oid::INT4RANGE, &mut buf)
        .unwrap_err();
    assert_eq!(buf, [0xAA]);
}

#[test]
fn range_encode_null_bound() {
    let mut buf = Vec::new();
    (Some(1_i32)..Some(5))
        .encode(oid::INT4RANGE, &mut buf)
        .unwrap();
    assert_eq!(buf[4], FLAG_LOWER_INCLUDED);

    buf.clear();
    (None..Some(5_i32))
        .encode(oid::INT4RANGE, &mut buf)
        .unwrap_err();
    assert!(buf.is_empty());
}

#[test]
fn range_encode_appends() {
    let mut buf = vec![0xAA, 0xBB];
    (1_i32..).encode(oid::INT4RANGE, &mut buf).unwrap();
    assert_eq!(buf[..2], [0xAA, 0xBB]);
    assert_eq!(buf[2..6], 9_i32.to_be_bytes());
}

#[test]
fn range_natural_oid() {
    assert_eq!(<Range<i16>>::NATURAL_OID, oid::INT4RANGE);
    assert_eq!(<Range<i32>>::NATURAL_OID, oid::INT4RANGE);
    assert_eq!(<RangeInclusive<i64>>::NATURAL_OID, oid::INT8RANGE);
    assert_eq!(<RangeFrom<i64>>::NATURAL_OID, oid::INT8RANGE);
    assert_eq!(<RangeTo<SystemTime>>::NATURAL_OID, oid::TSTZRANGE);
    assert_eq!(<RangeToInclusive<SystemTime>>::NATURAL_OID, oid::TSTZRANGE);
}

#[test]
fn range_encode_largest_integer() {
    let mut buf = Vec::new();
    (1_i32..=i32::MAX)
        .encode(oid::INT4RANGE, &mut buf)
        .unwrap_err();
    (..=i32::MAX).encode(oid::INT4RANGE, &mut buf).unwrap_err();
    (i32::MAX..=i32::MAX)
        .encode(oid::INT4RANGE, &mut buf)
        .unwrap_err();
    (1_i64..=i64::MAX)
        .encode(oid::INT8RANGE, &mut buf)
        .unwrap_err();
    (..=i64::MAX).encode(oid::INT8RANGE, &mut buf).unwrap_err();
    assert!(buf.is_empty());

    (1_i32..i32::MAX).encode(oid::INT4RANGE, &mut buf).unwrap();
    (i32::MAX..).encode(oid::INT4RANGE, &mut buf).unwrap();
    (1_i32..=i32::MAX).encode(oid::INT8RANGE, &mut buf).unwrap();
    (1_i64..i64::MAX).encode(oid::INT8RANGE, &mut buf).unwrap();
}

fn binary(flags: u8, bounds: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![flags];
    for bound in bounds {
        bytes.extend_from_slice(bound);
    }
    bytes
}

fn non_empty<T>(lower: Bound<T>, upper: Bound<T>) -> PgRange<T> {
    PgRange::NonEmpty { lower, upper }
}

#[test]
fn pg_range_encode() {
    let buf = encoded(
        non_empty(Bound::Excluded(1_i32), Bound::Included(5)),
        oid::INT4RANGE,
    );
    assert_eq!(buf[..4], 17_i32.to_be_bytes());
    assert_eq!(buf[4], FLAG_UPPER_INCLUDED);
    assert_eq!(buf[5..13], int4(1));
    assert_eq!(buf[13..], int4(5));

    let unbounded = encoded(
        non_empty::<i32>(Bound::Unbounded, Bound::Unbounded),
        oid::INT4RANGE,
    );
    assert_eq!(unbounded[..4], 1_i32.to_be_bytes());
    assert_eq!(
        unbounded[4..],
        [FLAG_LOWER_UNBOUNDED | FLAG_UPPER_UNBOUNDED]
    );

    let empty = encoded(PgRange::<i32>::Empty, oid::INT4RANGE);
    assert_eq!(empty[..4], 1_i32.to_be_bytes());
    assert_eq!(empty[4..], [FLAG_EMPTY]);
}

#[test]
fn pg_range_encode_invalid() {
    let mut buf = Vec::new();
    non_empty(Bound::Excluded(5_i32), Bound::Excluded(1))
        .encode(oid::INT4RANGE, &mut buf)
        .unwrap_err();
    non_empty(Bound::Excluded(i32::MAX), Bound::Unbounded)
        .encode(oid::INT4RANGE, &mut buf)
        .unwrap_err();
    non_empty(Bound::Unbounded, Bound::Included(i32::MAX))
        .encode(oid::INT4RANGE, &mut buf)
        .unwrap_err();
    PgRange::<i32>::Empty
        .encode(oid::INT4, &mut buf)
        .unwrap_err();
    assert!(buf.is_empty());

    non_empty(Bound::Excluded(i32::MAX), Bound::Included(i32::MAX))
        .encode(oid::INT4RANGE, &mut buf)
        .unwrap();
}

#[test]
fn pg_range_natural_oid() {
    assert_eq!(<PgRange<i32>>::NATURAL_OID, oid::INT4RANGE);
    assert_eq!(<PgRange<i64>>::NATURAL_OID, oid::INT8RANGE);
}

#[test]
fn pg_range_binary() {
    let decode = |bytes: &[u8]| PgRange::<i32>::from_binary(oid::INT4RANGE, bytes).unwrap();
    assert_eq!(
        decode(&binary(FLAG_LOWER_INCLUDED, &[&int4(1), &int4(5)])),
        non_empty(Bound::Included(1), Bound::Excluded(5))
    );
    assert_eq!(
        decode(&binary(FLAG_UPPER_INCLUDED, &[&int4(1), &int4(5)])),
        non_empty(Bound::Excluded(1), Bound::Included(5))
    );
    assert_eq!(
        decode(&binary(
            FLAG_LOWER_INCLUDED | FLAG_UPPER_UNBOUNDED,
            &[&int4(1)]
        )),
        non_empty(Bound::Included(1), Bound::Unbounded)
    );
    assert_eq!(
        decode(&binary(FLAG_LOWER_UNBOUNDED, &[&int4(5)])),
        non_empty(Bound::Unbounded, Bound::Excluded(5))
    );
    assert_eq!(
        decode(&binary(FLAG_LOWER_UNBOUNDED | FLAG_UPPER_UNBOUNDED, &[])),
        non_empty(Bound::Unbounded, Bound::Unbounded)
    );
    assert_eq!(decode(&binary(FLAG_EMPTY, &[])), PgRange::Empty);
    assert_eq!(
        PgRange::<i64>::from_binary(
            oid::INT8RANGE,
            &binary(FLAG_LOWER_INCLUDED, &[&int8(1), &int8(5)])
        )
        .unwrap(),
        non_empty(Bound::Included(1), Bound::Excluded(5))
    );
}

#[test]
fn pg_range_binary_invalid() {
    let decode = |oid: Oid, bytes: &[u8]| PgRange::<i32>::from_binary(oid, bytes);
    decode(oid::INT4RANGE, &[]).unwrap_err();
    decode(oid::INT4RANGE, &[FLAG_LOWER_INCLUDED]).unwrap_err();
    decode(oid::INT4RANGE, &binary(FLAG_LOWER_INCLUDED, &[&int4(1)])).unwrap_err();
    decode(
        oid::INT4RANGE,
        &binary(FLAG_LOWER_INCLUDED, &[&int4(1), &[0, 0, 0, 4, 0, 0]]),
    )
    .unwrap_err();
    decode(
        oid::INT4RANGE,
        &binary(FLAG_LOWER_INCLUDED, &[&int4(1), &int4(5), &[0]]),
    )
    .unwrap_err();
    decode(
        oid::INT4RANGE,
        &binary(FLAG_LOWER_INCLUDED, &[&int4(1), &[0xFF, 0xFF, 0xFF, 0xFF]]),
    )
    .unwrap_err();
    decode(oid::INT4RANGE, &binary(FLAG_EMPTY, &[&int4(1)])).unwrap_err();
    decode(
        oid::INT4,
        &binary(FLAG_LOWER_INCLUDED, &[&int4(1), &int4(5)]),
    )
    .unwrap_err();
    decode(
        oid::NUMRANGE,
        &binary(FLAG_LOWER_INCLUDED, &[&int4(1), &int4(5)]),
    )
    .unwrap_err();
}

#[test]
fn pg_range_text() {
    let decode = |text: &[u8]| PgRange::<i32>::from_text(oid::INT4RANGE, text).unwrap();
    assert_eq!(
        decode(b"[1,5)"),
        non_empty(Bound::Included(1), Bound::Excluded(5))
    );
    assert_eq!(
        decode(b"(1,5]"),
        non_empty(Bound::Excluded(1), Bound::Included(5))
    );
    assert_eq!(
        decode(b"[-3,)"),
        non_empty(Bound::Included(-3), Bound::Unbounded)
    );
    assert_eq!(
        decode(b"(,5)"),
        non_empty(Bound::Unbounded, Bound::Excluded(5))
    );
    assert_eq!(
        decode(b"(,)"),
        non_empty(Bound::Unbounded, Bound::Unbounded)
    );
    assert_eq!(decode(b"empty"), PgRange::Empty);
    assert_eq!(
        decode(b"[\"1\",\"5\")"),
        non_empty(Bound::Included(1), Bound::Excluded(5))
    );
}

#[test]
fn pg_range_text_invalid() {
    let decode = |oid: Oid, text: &[u8]| PgRange::<i32>::from_text(oid, text);
    decode(oid::INT4RANGE, b"").unwrap_err();
    decode(oid::INT4RANGE, b"[").unwrap_err();
    decode(oid::INT4RANGE, b"1,5").unwrap_err();
    decode(oid::INT4RANGE, b"[1,5").unwrap_err();
    decode(oid::INT4RANGE, b"[1 5)").unwrap_err();
    decode(oid::INT4RANGE, b"[1,5,9)").unwrap_err();
    decode(oid::INT4RANGE, b"[a,5)").unwrap_err();
    decode(oid::INT4RANGE, b"[\"1,5)").unwrap_err();
    decode(oid::INT4RANGE, b"[\"1\"5)").unwrap_err();
    decode(oid::INT4RANGE, b"[\"1\\\\\",5)").unwrap_err();
    decode(oid::INT4RANGE, b"[\"1\"\"2\",5)").unwrap_err();
    decode(oid::INT4, b"[1,5)").unwrap_err();
}

#[test]
fn pg_range_text_quoted_bounds() {
    let start = SystemTime::from_text(oid::TIMESTAMPTZ, b"2024-01-15 10:30:45+00").unwrap();
    let end = SystemTime::from_text(oid::TIMESTAMPTZ, b"2024-01-16 10:30:45+00").unwrap();
    let decode = |text: &[u8]| PgRange::<SystemTime>::from_text(oid::TSTZRANGE, text).unwrap();
    assert_eq!(
        decode(b"[\"2024-01-15 10:30:45+00\",\"2024-01-16 10:30:45+00\")"),
        non_empty(Bound::Included(start), Bound::Excluded(end))
    );
    assert_eq!(
        decode(b"[\"2024-01-15 10:30:45+00\",)"),
        non_empty(Bound::Included(start), Bound::Unbounded)
    );
    assert_eq!(
        decode(b"(,\"2024-01-16 10:30:45+00\"]"),
        non_empty(Bound::Unbounded, Bound::Included(end))
    );
}

#[test]
fn std_range_binary() {
    assert_eq!(
        <Range<i32>>::from_binary(
            oid::INT4RANGE,
            &binary(FLAG_LOWER_INCLUDED, &[&int4(1), &int4(5)])
        )
        .unwrap(),
        1..5
    );
    assert_eq!(
        <RangeInclusive<i32>>::from_binary(
            oid::INT4RANGE,
            &binary(
                FLAG_LOWER_INCLUDED | FLAG_UPPER_INCLUDED,
                &[&int4(1), &int4(5)]
            )
        )
        .unwrap(),
        1..=5
    );
    assert_eq!(
        <RangeFrom<i32>>::from_binary(
            oid::INT4RANGE,
            &binary(FLAG_LOWER_INCLUDED | FLAG_UPPER_UNBOUNDED, &[&int4(1)])
        )
        .unwrap(),
        1..
    );
    assert_eq!(
        <RangeTo<i32>>::from_binary(oid::INT4RANGE, &binary(FLAG_LOWER_UNBOUNDED, &[&int4(5)]))
            .unwrap(),
        ..5
    );
    assert_eq!(
        <RangeToInclusive<i32>>::from_binary(
            oid::INT4RANGE,
            &binary(FLAG_LOWER_UNBOUNDED | FLAG_UPPER_INCLUDED, &[&int4(5)])
        )
        .unwrap(),
        ..=5
    );
}

#[test]
fn std_range_text() {
    assert_eq!(
        <Range<i32>>::from_text(oid::INT4RANGE, b"[1,5)").unwrap(),
        1..5
    );
    assert_eq!(
        <RangeInclusive<i32>>::from_text(oid::INT4RANGE, b"[1,5]").unwrap(),
        1..=5
    );
    assert_eq!(
        <RangeFrom<i32>>::from_text(oid::INT4RANGE, b"[1,)").unwrap(),
        1..
    );
    assert_eq!(
        <RangeTo<i32>>::from_text(oid::INT4RANGE, b"(,5)").unwrap(),
        ..5
    );
    assert_eq!(
        <RangeToInclusive<i32>>::from_text(oid::INT4RANGE, b"(,5]").unwrap(),
        ..=5
    );
}

#[test]
fn std_range_bounds_mismatch() {
    <Range<i32>>::from_text(oid::INT4RANGE, b"empty").unwrap_err();
    <Range<i32>>::from_text(oid::INT4RANGE, b"[1,5]").unwrap_err();
    <Range<i32>>::from_text(oid::INT4RANGE, b"(1,5)").unwrap_err();
    <Range<i32>>::from_text(oid::INT4RANGE, b"[1,)").unwrap_err();
    <Range<i32>>::from_text(oid::INT4RANGE, b"(,5)").unwrap_err();
    <Range<i32>>::from_text(oid::INT4RANGE, b"(,)").unwrap_err();
    <RangeInclusive<i32>>::from_text(oid::INT4RANGE, b"[1,5)").unwrap_err();
    <RangeFrom<i32>>::from_text(oid::INT4RANGE, b"[1,5)").unwrap_err();
    <RangeFrom<i32>>::from_text(oid::INT4RANGE, b"(1,)").unwrap_err();
    <RangeTo<i32>>::from_text(oid::INT4RANGE, b"(,5]").unwrap_err();
    <RangeToInclusive<i32>>::from_text(oid::INT4RANGE, b"(,5)").unwrap_err();
    <Range<i32>>::from_binary(oid::INT4RANGE, &binary(FLAG_EMPTY, &[])).unwrap_err();
}

#[test]
fn pg_range_roundtrip() {
    for range in [
        PgRange::Empty,
        non_empty(Bound::Included(1_i32), Bound::Excluded(5)),
        non_empty(Bound::Excluded(1), Bound::Included(5)),
        non_empty(Bound::Included(1), Bound::Unbounded),
        non_empty(Bound::Unbounded, Bound::Included(5)),
        non_empty(Bound::Unbounded, Bound::Unbounded),
    ] {
        let buf = encoded(range, oid::INT4RANGE);
        assert_eq!(
            PgRange::<i32>::from_binary(oid::INT4RANGE, &buf[4..]).unwrap(),
            range
        );
    }
}
