use super::*;

#[test]
fn i32_text() {
    assert_eq!(i32::from_text(oid::INT4, b"12345").unwrap(), 12345);
    assert_eq!(i32::from_text(oid::INT4, b"-12345").unwrap(), -12345);
}

#[test]
fn i32_binary() {
    assert_eq!(
        i32::from_binary(oid::INT4, &[0, 0, 0x30, 0x39]).unwrap(),
        12345
    );
}

#[test]
fn f64_text() {
    assert_eq!(f64::from_text(oid::FLOAT8, b"3.15").unwrap(), 3.15);
}

#[test]
fn widening() {
    // i32 can decode INT2
    assert_eq!(i32::from_binary(oid::INT2, &[0, 42]).unwrap(), 42);
    // i64 can decode INT4
    assert_eq!(i64::from_binary(oid::INT4, &[0, 0, 0, 42]).unwrap(), 42);
    // f64 can decode FLOAT4
    let f32_bytes = 3.15_f32.to_be_bytes();
    assert!((f64::from_binary(oid::FLOAT4, &f32_bytes).unwrap() - 3.15).abs() < 0.001);
}

#[test]
fn type_mismatch() {
    // Trying to decode TEXT as i32 should fail
    i32::from_text(oid::TEXT, b"123").unwrap_err();
}

#[test]
fn i8_encoding() {
    let mut buf = Vec::new();
    42i8.encode(oid::INT2, &mut buf).unwrap();
    // Length prefix (4 bytes) + i16 value (2 bytes)
    assert_eq!(buf.len(), 6);
    assert_eq!(&buf[0..4], &2_i32.to_be_bytes()); // length = 2
    assert_eq!(&buf[4..6], &42_i16.to_be_bytes());
}

#[test]
fn i8_decoding() {
    assert_eq!(
        i8::from_binary(oid::INT2, &(-128_i16).to_be_bytes()).unwrap(),
        -128
    );
    assert_eq!(
        i8::from_binary(oid::INT4, &127_i32.to_be_bytes()).unwrap(),
        127
    );
    assert_eq!(
        i8::from_binary(oid::INT8, &42_i64.to_be_bytes()).unwrap(),
        42
    );
    assert_eq!(i8::from_text(oid::INT4, b"-128").unwrap(), -128);

    i8::from_binary(oid::INT2, &128_i16.to_be_bytes()).unwrap_err();
    i8::from_binary(oid::INT4, &(-129_i32).to_be_bytes()).unwrap_err();
    i8::from_binary(oid::INT8, &i64::MAX.to_be_bytes()).unwrap_err();
    i8::from_text(oid::INT8, b"128").unwrap_err();
    i8::from_binary(oid::TEXT, &[1]).unwrap_err();
}

#[test]
fn u8_encoding() {
    let mut buf = Vec::new();
    200u8.encode(oid::INT2, &mut buf).unwrap();
    assert_eq!(buf.len(), 6);
    assert_eq!(&buf[0..4], &2_i32.to_be_bytes());
    assert_eq!(&buf[4..6], &200_i16.to_be_bytes());
}

#[test]
fn u16_encoding() {
    let mut buf = Vec::new();
    50000u16.encode(oid::INT4, &mut buf).unwrap();
    // u16 encodes as INT4
    assert_eq!(buf.len(), 8);
    assert_eq!(&buf[0..4], &4_i32.to_be_bytes());
    assert_eq!(&buf[4..8], &50000_i32.to_be_bytes());
}

#[test]
fn u16_overflow_to_int2() {
    // 50000 > i16::MAX, should fail when encoding to INT2
    let result = 50000u16.encode(oid::INT2, &mut Vec::new());
    assert!(result.is_err());

    // But 1000 should work
    let mut buf = Vec::new();
    1000u16.encode(oid::INT2, &mut buf).unwrap();
    assert_eq!(&buf[4..6], &1000_i16.to_be_bytes());
}

#[test]
fn u32_encoding() {
    let mut buf = Vec::new();
    3_000_000_000u32.encode(oid::INT8, &mut buf).unwrap();
    // u32 encodes as INT8
    assert_eq!(buf.len(), 12);
    assert_eq!(&buf[0..4], &8_i32.to_be_bytes());
    assert_eq!(&buf[4..12], &3_000_000_000_i64.to_be_bytes());
}

#[test]
fn u32_overflow_to_int4() {
    // 3 billion > i32::MAX, should fail when encoding to INT4
    let result = 3_000_000_000u32.encode(oid::INT4, &mut Vec::new());
    assert!(result.is_err());

    // But 1 million should work
    let mut buf = Vec::new();
    1_000_000u32.encode(oid::INT4, &mut buf).unwrap();
    assert_eq!(&buf[4..8], &1_000_000_i32.to_be_bytes());
}

#[test]
fn u64_encoding() {
    let mut buf = Vec::new();
    1000u64.encode(oid::INT8, &mut buf).unwrap();
    assert_eq!(buf.len(), 12);
    assert_eq!(&buf[0..4], &8_i32.to_be_bytes());
    assert_eq!(&buf[4..12], &1000_i64.to_be_bytes());
}

#[test]
fn f64_overflow_to_float4() {
    1e300_f64.encode(oid::FLOAT4, &mut Vec::new()).unwrap_err();
    (-1e300_f64)
        .encode(oid::FLOAT4, &mut Vec::new())
        .unwrap_err();

    let mut buf = Vec::new();
    1.5_f64.encode(oid::FLOAT4, &mut buf).unwrap();
    assert_eq!(&buf[4..8], &1.5_f32.to_be_bytes());

    buf.clear();
    f64::INFINITY.encode(oid::FLOAT4, &mut buf).unwrap();
    assert_eq!(&buf[4..8], &f32::INFINITY.to_be_bytes());

    buf.clear();
    f64::NAN.encode(oid::FLOAT4, &mut buf).unwrap();
    assert!(f32::from_be_bytes(buf[4..8].try_into().unwrap()).is_nan());
}

#[test]
fn u64_overflow() {
    // u64::MAX > i64::MAX, should fail
    let result = u64::MAX.encode(oid::INT8, &mut Vec::new());
    assert!(result.is_err());

    // But i64::MAX as u64 should work
    let mut buf = Vec::new();
    (i64::MAX as u64).encode(oid::INT8, &mut buf).unwrap();
    assert_eq!(&buf[4..12], &i64::MAX.to_be_bytes());
}

#[test]
fn i16_narrowing() {
    assert_eq!(
        i16::from_binary(oid::INT4, &i32::from(i16::MAX).to_be_bytes()).unwrap(),
        i16::MAX
    );
    assert_eq!(
        i16::from_binary(oid::INT4, &i32::from(i16::MIN).to_be_bytes()).unwrap(),
        i16::MIN
    );
    i16::from_binary(oid::INT4, &(i32::from(i16::MAX) + 1).to_be_bytes()).unwrap_err();
    i16::from_binary(oid::INT4, &(i32::from(i16::MIN) - 1).to_be_bytes()).unwrap_err();

    assert_eq!(
        i16::from_binary(oid::INT8, &i64::from(i16::MAX).to_be_bytes()).unwrap(),
        i16::MAX
    );
    assert_eq!(
        i16::from_binary(oid::INT8, &i64::from(i16::MIN).to_be_bytes()).unwrap(),
        i16::MIN
    );
    i16::from_binary(oid::INT8, &(i64::from(i16::MAX) + 1).to_be_bytes()).unwrap_err();
    i16::from_binary(oid::INT8, &(i64::from(i16::MIN) - 1).to_be_bytes()).unwrap_err();
    i16::from_binary(oid::INT8, &i64::MAX.to_be_bytes()).unwrap_err();
    i16::from_binary(oid::INT8, &i64::MIN.to_be_bytes()).unwrap_err();
}

#[test]
fn i32_narrowing() {
    assert_eq!(
        i32::from_binary(oid::INT8, &i64::from(i32::MAX).to_be_bytes()).unwrap(),
        i32::MAX
    );
    assert_eq!(
        i32::from_binary(oid::INT8, &i64::from(i32::MIN).to_be_bytes()).unwrap(),
        i32::MIN
    );
    i32::from_binary(oid::INT8, &(i64::from(i32::MAX) + 1).to_be_bytes()).unwrap_err();
    i32::from_binary(oid::INT8, &(i64::from(i32::MIN) - 1).to_be_bytes()).unwrap_err();
}

#[test]
fn u8_decoding() {
    assert_eq!(u8::from_binary(oid::INT2, &0_i16.to_be_bytes()).unwrap(), 0);
    assert_eq!(
        u8::from_binary(oid::INT2, &255_i16.to_be_bytes()).unwrap(),
        u8::MAX
    );
    u8::from_binary(oid::INT2, &256_i16.to_be_bytes()).unwrap_err();
    u8::from_binary(oid::INT2, &(-1_i16).to_be_bytes()).unwrap_err();
    u8::from_binary(oid::INT2, &i16::MIN.to_be_bytes()).unwrap_err();

    assert_eq!(u8::from_binary(oid::INT4, &0_i32.to_be_bytes()).unwrap(), 0);
    assert_eq!(
        u8::from_binary(oid::INT4, &255_i32.to_be_bytes()).unwrap(),
        u8::MAX
    );
    u8::from_binary(oid::INT4, &256_i32.to_be_bytes()).unwrap_err();
    u8::from_binary(oid::INT4, &(-1_i32).to_be_bytes()).unwrap_err();

    assert_eq!(u8::from_binary(oid::INT8, &0_i64.to_be_bytes()).unwrap(), 0);
    assert_eq!(
        u8::from_binary(oid::INT8, &255_i64.to_be_bytes()).unwrap(),
        u8::MAX
    );
    u8::from_binary(oid::INT8, &256_i64.to_be_bytes()).unwrap_err();
    u8::from_binary(oid::INT8, &(-1_i64).to_be_bytes()).unwrap_err();
    u8::from_binary(oid::INT8, &i64::MIN.to_be_bytes()).unwrap_err();
}

#[test]
fn u16_decoding() {
    assert_eq!(
        u16::from_binary(oid::INT2, &0_i16.to_be_bytes()).unwrap(),
        0
    );
    assert_eq!(
        u16::from_binary(oid::INT2, &i16::MAX.to_be_bytes()).unwrap(),
        i16::MAX.cast_unsigned()
    );
    u16::from_binary(oid::INT2, &(-1_i16).to_be_bytes()).unwrap_err();
    u16::from_binary(oid::INT2, &i16::MIN.to_be_bytes()).unwrap_err();

    assert_eq!(
        u16::from_binary(oid::INT4, &0_i32.to_be_bytes()).unwrap(),
        0
    );
    assert_eq!(
        u16::from_binary(oid::INT4, &i32::from(u16::MAX).to_be_bytes()).unwrap(),
        u16::MAX
    );
    u16::from_binary(oid::INT4, &(i32::from(u16::MAX) + 1).to_be_bytes()).unwrap_err();
    u16::from_binary(oid::INT4, &(-1_i32).to_be_bytes()).unwrap_err();

    assert_eq!(
        u16::from_binary(oid::INT8, &0_i64.to_be_bytes()).unwrap(),
        0
    );
    assert_eq!(
        u16::from_binary(oid::INT8, &i64::from(u16::MAX).to_be_bytes()).unwrap(),
        u16::MAX
    );
    u16::from_binary(oid::INT8, &(i64::from(u16::MAX) + 1).to_be_bytes()).unwrap_err();
    u16::from_binary(oid::INT8, &(-1_i64).to_be_bytes()).unwrap_err();
}

#[test]
fn u32_decoding() {
    assert_eq!(
        u32::from_binary(oid::INT2, &0_i16.to_be_bytes()).unwrap(),
        0
    );
    assert_eq!(
        u32::from_binary(oid::INT2, &i16::MAX.to_be_bytes()).unwrap(),
        u32::from(i16::MAX.cast_unsigned())
    );
    u32::from_binary(oid::INT2, &(-1_i16).to_be_bytes()).unwrap_err();

    assert_eq!(
        u32::from_binary(oid::INT4, &0_i32.to_be_bytes()).unwrap(),
        0
    );
    assert_eq!(
        u32::from_binary(oid::INT4, &i32::MAX.to_be_bytes()).unwrap(),
        i32::MAX.cast_unsigned()
    );
    u32::from_binary(oid::INT4, &(-1_i32).to_be_bytes()).unwrap_err();
    u32::from_binary(oid::INT4, &i32::MIN.to_be_bytes()).unwrap_err();

    assert_eq!(
        u32::from_binary(oid::INT8, &0_i64.to_be_bytes()).unwrap(),
        0
    );
    assert_eq!(
        u32::from_binary(oid::INT8, &i64::from(u32::MAX).to_be_bytes()).unwrap(),
        u32::MAX
    );
    u32::from_binary(oid::INT8, &(i64::from(u32::MAX) + 1).to_be_bytes()).unwrap_err();
    u32::from_binary(oid::INT8, &(-1_i64).to_be_bytes()).unwrap_err();
}

#[test]
fn u64_decoding() {
    assert_eq!(
        u64::from_binary(oid::INT2, &0_i16.to_be_bytes()).unwrap(),
        0
    );
    assert_eq!(
        u64::from_binary(oid::INT2, &i16::MAX.to_be_bytes()).unwrap(),
        u64::from(i16::MAX.cast_unsigned())
    );
    u64::from_binary(oid::INT2, &(-1_i16).to_be_bytes()).unwrap_err();

    assert_eq!(
        u64::from_binary(oid::INT4, &0_i32.to_be_bytes()).unwrap(),
        0
    );
    assert_eq!(
        u64::from_binary(oid::INT4, &i32::MAX.to_be_bytes()).unwrap(),
        u64::from(i32::MAX.cast_unsigned())
    );
    u64::from_binary(oid::INT4, &(-1_i32).to_be_bytes()).unwrap_err();

    assert_eq!(
        u64::from_binary(oid::INT8, &0_i64.to_be_bytes()).unwrap(),
        0
    );
    assert_eq!(
        u64::from_binary(oid::INT8, &i64::MAX.to_be_bytes()).unwrap(),
        i64::MAX.cast_unsigned()
    );
    u64::from_binary(oid::INT8, &(-1_i64).to_be_bytes()).unwrap_err();
    u64::from_binary(oid::INT8, &i64::MIN.to_be_bytes()).unwrap_err();
}

#[test]
fn narrowing_text() {
    assert_eq!(i16::from_text(oid::INT4, b"-32768").unwrap(), i16::MIN);
    i16::from_text(oid::INT4, b"32768").unwrap_err();
    assert_eq!(i32::from_text(oid::INT8, b"2147483647").unwrap(), i32::MAX);
    i32::from_text(oid::INT8, b"-2147483649").unwrap_err();

    assert_eq!(u8::from_text(oid::INT2, b"255").unwrap(), u8::MAX);
    u8::from_text(oid::INT2, b"256").unwrap_err();
    u8::from_text(oid::INT2, b"-1").unwrap_err();

    assert_eq!(u16::from_text(oid::INT4, b"65535").unwrap(), u16::MAX);
    u16::from_text(oid::INT4, b"65536").unwrap_err();
    u16::from_text(oid::INT2, b"-1").unwrap_err();

    assert_eq!(u32::from_text(oid::INT8, b"4294967295").unwrap(), u32::MAX);
    u32::from_text(oid::INT8, b"4294967296").unwrap_err();
    u32::from_text(oid::INT4, b"-1").unwrap_err();

    assert_eq!(
        u64::from_text(oid::INT8, b"9223372036854775807").unwrap(),
        i64::MAX.cast_unsigned()
    );
    u64::from_text(oid::INT8, b"-1").unwrap_err();
    u64::from_text(oid::INT8, b"").unwrap_err();
    u64::from_text(oid::INT8, b"1.5").unwrap_err();
}

#[test]
fn non_integer_oid() {
    let mut buf = Vec::new();
    i16::from_binary(oid::TEXT, &[0, 1]).unwrap_err();
    i16::from_binary(oid::FLOAT8, &1.0_f64.to_be_bytes()).unwrap_err();
    i16::from_text(oid::FLOAT8, b"1").unwrap_err();
    1_i16.encode(oid::TEXT, &mut buf).unwrap_err();
    1_i16.encode(oid::UUID, &mut buf).unwrap_err();
    1_i64.encode(oid::NUMERIC, &mut buf).unwrap_err();

    u32::from_binary(oid::TEXT, &[0, 0, 0, 1]).unwrap_err();
    u32::from_binary(oid::FLOAT4, &1.0_f32.to_be_bytes()).unwrap_err();
    u32::from_text(oid::TEXT, b"1").unwrap_err();
    1_u32.encode(oid::TEXT, &mut buf).unwrap_err();
    1_u32.encode(oid::NUMERIC, &mut buf).unwrap_err();
    1_u8.encode(oid::BOOL, &mut buf).unwrap_err();
    assert!(buf.is_empty());

    1_u32.encode(oid::INT4, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 4, 0, 0, 0, 1]);
}

#[test]
fn integer_to_float_encoding() {
    let mut buf = Vec::new();
    5_i32.encode(oid::FLOAT8, &mut buf).unwrap();
    assert_eq!(&buf[0..4], &8_i32.to_be_bytes());
    assert_eq!(&buf[4..12], &5.0_f64.to_be_bytes());

    buf.clear();
    u16::MAX.encode(oid::FLOAT4, &mut buf).unwrap();
    assert_eq!(&buf[0..4], &4_i32.to_be_bytes());
    assert_eq!(&buf[4..8], &65535.0_f32.to_be_bytes());

    buf.clear();
    (-3_i64).encode(oid::FLOAT4, &mut buf).unwrap();
    assert_eq!(&buf[4..8], &(-3.0_f32).to_be_bytes());

    buf.clear();
    0_u64.encode(oid::FLOAT8, &mut buf).unwrap();
    assert_eq!(&buf[4..12], &0.0_f64.to_be_bytes());

    buf.clear();
    (1_i32 << 24).encode(oid::FLOAT4, &mut buf).unwrap();
    assert_eq!(&buf[4..8], &16777216.0_f32.to_be_bytes());
    ((1_i32 << 24) + 1)
        .encode(oid::FLOAT4, &mut Vec::new())
        .unwrap_err();
    ((1_u32 << 24) + 1)
        .encode(oid::FLOAT4, &mut Vec::new())
        .unwrap_err();

    buf.clear();
    (1_i64 << 53).encode(oid::FLOAT8, &mut buf).unwrap();
    assert_eq!(&buf[4..12], &9007199254740992.0_f64.to_be_bytes());
    ((1_i64 << 53) + 1)
        .encode(oid::FLOAT8, &mut Vec::new())
        .unwrap_err();
    (-(1_i64 << 53) - 1)
        .encode(oid::FLOAT8, &mut Vec::new())
        .unwrap_err();

    buf.clear();
    i64::MIN.encode(oid::FLOAT4, &mut buf).unwrap();
    assert_eq!(&buf[4..8], &(i64::MIN as f32).to_be_bytes());
    i64::MAX.encode(oid::FLOAT8, &mut Vec::new()).unwrap_err();
    u64::MAX.encode(oid::FLOAT8, &mut Vec::new()).unwrap_err();
    u64::MAX.encode(oid::FLOAT4, &mut Vec::new()).unwrap_err();

    buf.clear();
    (1_u64 << 63).encode(oid::FLOAT4, &mut buf).unwrap();
    assert_eq!(&buf[4..8], &((1_u64 << 63) as f32).to_be_bytes());
}

#[test]
fn float_from_integer() {
    assert_eq!(
        f32::from_binary(oid::INT2, &i16::MIN.to_be_bytes()).unwrap(),
        -32768.0
    );
    assert_eq!(
        f64::from_binary(oid::INT2, &i16::MAX.to_be_bytes()).unwrap(),
        32767.0
    );
    assert_eq!(
        f64::from_binary(oid::INT4, &i32::MIN.to_be_bytes()).unwrap(),
        -2147483648.0
    );
    assert_eq!(
        f64::from_binary(oid::INT8, &(1_i64 << 53).to_be_bytes()).unwrap(),
        9007199254740992.0
    );
    assert_eq!(
        f64::from_binary(oid::INT8, &i64::MIN.to_be_bytes()).unwrap(),
        i64::MIN as f64
    );
    assert_eq!(
        f32::from_binary(oid::INT4, &(1_i32 << 24).to_be_bytes()).unwrap(),
        16777216.0
    );
    assert_eq!(
        f32::from_binary(oid::INT8, &(-5_i64).to_be_bytes()).unwrap(),
        -5.0
    );

    f32::from_binary(oid::INT4, &((1_i32 << 24) + 1).to_be_bytes()).unwrap_err();
    f32::from_binary(oid::INT8, &i64::MAX.to_be_bytes()).unwrap_err();
    f64::from_binary(oid::INT8, &((1_i64 << 53) + 1).to_be_bytes()).unwrap_err();
    f64::from_binary(oid::INT8, &i64::MAX.to_be_bytes()).unwrap_err();
    f64::from_binary(oid::INT4, &[0, 0, 1]).unwrap_err();

    assert_eq!(f64::from_text(oid::INT4, b"-42").unwrap(), -42.0);
    assert_eq!(f32::from_text(oid::INT2, b"7").unwrap(), 7.0);
    f32::from_text(oid::INT8, b"16777217").unwrap_err();
    f64::from_text(oid::INT8, b"9007199254740993").unwrap_err();
    f64::from_text(oid::INT4, b"1.5").unwrap_err();
}

#[test]
fn invalid_length() {
    i32::from_binary(oid::INT4, &[0, 0, 1]).unwrap_err();
    i32::from_binary(oid::INT4, &[0, 0, 0, 0, 1]).unwrap_err();
    i32::from_binary(oid::INT2, &[0, 0, 0, 1]).unwrap_err();
    i64::from_binary(oid::INT8, &[0, 0, 0, 1]).unwrap_err();
    i16::from_binary(oid::INT2, &[]).unwrap_err();
    u16::from_binary(oid::INT2, &[1]).unwrap_err();
    u32::from_binary(oid::INT4, &[0, 0, 1]).unwrap_err();
    u64::from_binary(oid::INT8, &[0, 0, 0, 0, 0, 0, 1]).unwrap_err();
    u8::from_binary(oid::INT2, &[0, 0, 1]).unwrap_err();
}

#[test]
fn i16_round_trip() {
    let mut buf = Vec::new();
    for target in [oid::INT2, oid::INT4, oid::INT8] {
        for value in [i16::MIN, -1234, 0, 1234, i16::MAX] {
            buf.clear();
            value.encode(target, &mut buf).unwrap();
            let len = usize::try_from(i32::from_be_bytes(buf[0..4].try_into().unwrap())).unwrap();
            assert_eq!(buf.len(), 4 + len);
            assert_eq!(i16::from_binary(target, &buf[4..]).unwrap(), value);
        }
    }
}

#[test]
fn u32_round_trip() {
    let mut buf = Vec::new();
    for target in [oid::INT2, oid::INT4, oid::INT8] {
        for value in [0_u32, 1234, u32::from(i16::MAX.cast_unsigned())] {
            buf.clear();
            value.encode(target, &mut buf).unwrap();
            let len = usize::try_from(i32::from_be_bytes(buf[0..4].try_into().unwrap())).unwrap();
            assert_eq!(buf.len(), 4 + len);
            assert_eq!(u32::from_binary(target, &buf[4..]).unwrap(), value);
        }
    }
    buf.clear();
    u32::MAX.encode(oid::INT8, &mut buf).unwrap();
    assert_eq!(u32::from_binary(oid::INT8, &buf[4..]).unwrap(), u32::MAX);
}

// Helper to build NUMERIC binary representation
fn make_numeric(ndigits: i16, weight: i16, sign: u16, dscale: u16, digits: &[i16]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&ndigits.to_be_bytes());
    buf.extend_from_slice(&weight.to_be_bytes());
    buf.extend_from_slice(&sign.to_be_bytes());
    buf.extend_from_slice(&dscale.to_be_bytes());
    for &d in digits {
        buf.extend_from_slice(&d.to_be_bytes());
    }
    buf
}

#[test]
fn numeric_to_f64_basic() {
    // 123.45
    let bytes = make_numeric(2, 0, 0x0000, 2, &[123, 4500]);
    let result = f64::from_binary(oid::NUMERIC, &bytes).unwrap();
    assert!((result - 123.45).abs() < 0.001);
}

#[test]
fn numeric_to_f64_negative() {
    // -123.45
    let bytes = make_numeric(2, 0, 0x4000, 2, &[123, 4500]);
    let result = f64::from_binary(oid::NUMERIC, &bytes).unwrap();
    assert!((result + 123.45).abs() < 0.001);
}

#[test]
fn numeric_to_f64_special() {
    // NaN
    let bytes1 = make_numeric(0, 0, 0xC000, 0, &[]);
    assert!(f64::from_binary(oid::NUMERIC, &bytes1).unwrap().is_nan());

    // +Infinity
    let bytes2 = make_numeric(0, 0, 0xD000, 0, &[]);
    assert_eq!(
        f64::from_binary(oid::NUMERIC, &bytes2).unwrap(),
        f64::INFINITY
    );

    // -Infinity
    let bytes3 = make_numeric(0, 0, 0xF000, 0, &[]);
    assert_eq!(
        f64::from_binary(oid::NUMERIC, &bytes3).unwrap(),
        f64::NEG_INFINITY
    );
}

#[test]
fn numeric_to_f32_basic() {
    // 123.45
    let bytes = make_numeric(2, 0, 0x0000, 2, &[123, 4500]);
    let result = f32::from_binary(oid::NUMERIC, &bytes).unwrap();
    assert!((result - 123.45).abs() < 0.01);
}

#[test]
fn numeric_to_f32_special() {
    // NaN
    let bytes1 = make_numeric(0, 0, 0xC000, 0, &[]);
    assert!(f32::from_binary(oid::NUMERIC, &bytes1).unwrap().is_nan());

    // +Infinity
    let bytes2 = make_numeric(0, 0, 0xD000, 0, &[]);
    assert_eq!(
        f32::from_binary(oid::NUMERIC, &bytes2).unwrap(),
        f32::INFINITY
    );

    // -Infinity
    let bytes3 = make_numeric(0, 0, 0xF000, 0, &[]);
    assert_eq!(
        f32::from_binary(oid::NUMERIC, &bytes3).unwrap(),
        f32::NEG_INFINITY
    );
}

#[test]
fn f64_from_text_special() {
    assert!(f64::from_text(oid::NUMERIC, b"NaN").unwrap().is_nan());
    assert_eq!(
        f64::from_text(oid::NUMERIC, b"Infinity").unwrap(),
        f64::INFINITY
    );
    assert_eq!(
        f64::from_text(oid::NUMERIC, b"-Infinity").unwrap(),
        f64::NEG_INFINITY
    );
}

#[test]
fn f32_from_text_special() {
    assert!(f32::from_text(oid::NUMERIC, b"NaN").unwrap().is_nan());
    assert_eq!(
        f32::from_text(oid::NUMERIC, b"Infinity").unwrap(),
        f32::INFINITY
    );
    assert_eq!(
        f32::from_text(oid::NUMERIC, b"-Infinity").unwrap(),
        f32::NEG_INFINITY
    );
}

fn char_server_text(byte: u8) -> Vec<u8> {
    match byte {
        0 => Vec::new(),
        0x01..=0x7F => vec![byte],
        _ => format!("\\{:03o}", byte).into_bytes(),
    }
}

#[test]
fn char_binary_decode() {
    assert_eq!(i8::from_binary(oid::CHAR, &[0x00]).unwrap(), 0);
    assert_eq!(i8::from_binary(oid::CHAR, &[0x41]).unwrap(), 65);
    assert_eq!(i8::from_binary(oid::CHAR, &[0x7F]).unwrap(), 127);
    assert_eq!(i8::from_binary(oid::CHAR, &[0x80]).unwrap(), -128);
    assert_eq!(i8::from_binary(oid::CHAR, &[0xFF]).unwrap(), -1);

    assert_eq!(u8::from_binary(oid::CHAR, &[0x00]).unwrap(), 0);
    assert_eq!(u8::from_binary(oid::CHAR, &[0x41]).unwrap(), 65);
    assert_eq!(u8::from_binary(oid::CHAR, &[0x7F]).unwrap(), 127);
    assert_eq!(u8::from_binary(oid::CHAR, &[0x80]).unwrap(), 128);
    assert_eq!(u8::from_binary(oid::CHAR, &[0xFF]).unwrap(), 255);
}

#[test]
fn char_binary_invalid_length() {
    i8::from_binary(oid::CHAR, &[]).unwrap_err();
    i8::from_binary(oid::CHAR, &[0, 1]).unwrap_err();
    u8::from_binary(oid::CHAR, &[]).unwrap_err();
    u8::from_binary(oid::CHAR, &[0, 1]).unwrap_err();
    u8::from_binary(oid::CHAR, &[0, 0, 0, 1]).unwrap_err();
}

#[test]
fn char_text_decode() {
    assert_eq!(i8::from_text(oid::CHAR, b"").unwrap(), 0);
    assert_eq!(i8::from_text(oid::CHAR, b"A").unwrap(), 65);
    assert_eq!(i8::from_text(oid::CHAR, b"\x7F").unwrap(), 127);
    assert_eq!(i8::from_text(oid::CHAR, b"\\200").unwrap(), -128);
    assert_eq!(i8::from_text(oid::CHAR, b"\\377").unwrap(), -1);

    assert_eq!(u8::from_text(oid::CHAR, b"").unwrap(), 0);
    assert_eq!(u8::from_text(oid::CHAR, b"A").unwrap(), 65);
    assert_eq!(u8::from_text(oid::CHAR, b"\\").unwrap(), b'\\');
    assert_eq!(u8::from_text(oid::CHAR, b"6").unwrap(), b'6');
    assert_eq!(u8::from_text(oid::CHAR, b"\\200").unwrap(), 128);
    assert_eq!(u8::from_text(oid::CHAR, b"\\377").unwrap(), 255);
}

#[test]
fn char_text_decode_malformed() {
    for bytes in [
        &b"AB"[..],
        b"65",
        b"\\400",
        b"\\777",
        b"\\800",
        b"\\899",
        b"\\280",
        b"\\208",
        b"\\20",
        b"\\3777",
        b"\\x41",
        b"200",
        b"\\\\",
    ] {
        assert!(
            i8::from_text(oid::CHAR, bytes).is_err(),
            "i8 accepted {:?}",
            bytes
        );
        assert!(
            u8::from_text(oid::CHAR, bytes).is_err(),
            "u8 accepted {:?}",
            bytes
        );
    }
}

#[test]
fn char_text_decode_rejects_forms_charout_never_produces() {
    let accepted: Vec<_> = [&b"\x00"[..], b"\x80", b"\xFF", b"\\000", b"\\101", b"\\177"]
        .into_iter()
        .filter_map(|bytes| {
            let unsigned = u8::from_text(oid::CHAR, bytes).ok()?;
            Some((bytes, unsigned, i8::from_text(oid::CHAR, bytes).ok()))
        })
        .collect();
    assert_eq!(accepted, []);
}

#[test]
fn char_encode() {
    let mut buf = Vec::new();
    65i8.encode(oid::CHAR, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 1, 0x41]);

    buf.clear();
    (-1i8).encode(oid::CHAR, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 1, 0xFF]);

    buf.clear();
    i8::MIN.encode(oid::CHAR, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 1, 0x80]);

    buf.clear();
    0i8.encode(oid::CHAR, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 1, 0x00]);

    buf.clear();
    255u8.encode(oid::CHAR, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 1, 0xFF]);

    buf.clear();
    128u8.encode(oid::CHAR, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 1, 0x80]);

    buf.clear();
    0u8.encode(oid::CHAR, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 1, 0x00]);

    let mut appended = vec![0xAA];
    7u8.encode(oid::CHAR, &mut appended).unwrap();
    7i8.encode(oid::CHAR, &mut appended).unwrap();
    assert_eq!(appended, [0xAA, 0, 0, 0, 1, 7, 0, 0, 0, 1, 7]);
}

#[test]
fn char_round_trip_all_bytes() {
    for byte in 0..=u8::MAX {
        let mut buf = Vec::new();
        byte.encode(oid::CHAR, &mut buf).unwrap();
        assert_eq!(buf, [0, 0, 0, 1, byte]);
        assert_eq!(u8::from_binary(oid::CHAR, &buf[4..]).unwrap(), byte);
        assert_eq!(
            u8::from_text(oid::CHAR, &char_server_text(byte)).unwrap(),
            byte,
            "u8 text {:?}",
            char_server_text(byte)
        );

        let signed = byte as i8;
        let mut signed_buf = Vec::new();
        signed.encode(oid::CHAR, &mut signed_buf).unwrap();
        assert_eq!(signed_buf, [0, 0, 0, 1, byte]);
        assert_eq!(
            i8::from_binary(oid::CHAR, &signed_buf[4..]).unwrap(),
            signed
        );
        assert_eq!(
            i8::from_text(oid::CHAR, &char_server_text(byte)).unwrap(),
            signed,
            "i8 text {:?}",
            char_server_text(byte)
        );
    }
}

#[test]
fn char_natural_oid_unchanged() {
    assert_eq!(<i8 as ToWireValue>::NATURAL_OID, oid::INT2);
    assert_eq!(<u8 as ToWireValue>::NATURAL_OID, oid::INT2);
}

#[test]
fn char_does_not_change_integer_paths() {
    assert_eq!(i8::from_text(oid::INT2, b"65").unwrap(), 65);
    assert_eq!(u8::from_text(oid::INT2, b"65").unwrap(), 65);
    i8::from_text(oid::INT2, b"A").unwrap_err();
    u8::from_text(oid::INT4, b"").unwrap_err();
    i8::from_binary(oid::INT2, &[0x41]).unwrap_err();
    assert_eq!(u8::from_binary(oid::INT2, &[0, 0xFF]).unwrap(), 255);
    u8::from_binary(oid::INT2, &[0xFF, 0xFF]).unwrap_err();
    assert_eq!(i8::from_binary(oid::INT2, &[0xFF, 0xFF]).unwrap(), -1);

    let mut buf = Vec::new();
    (-1i8).encode(oid::INT2, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 2, 0xFF, 0xFF]);
    buf.clear();
    255u8.encode(oid::INT4, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 4, 0, 0, 0, 0xFF]);
    buf.clear();
    (-1i8).encode(oid::INT8, &mut buf).unwrap();
    assert_eq!(
        buf,
        [0, 0, 0, 8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    buf.clear();
    255u8.encode(oid::FLOAT4, &mut buf).unwrap();
    assert_eq!(&buf[4..], &255_f32.to_be_bytes());
    buf.clear();
    (-128i8).encode(oid::FLOAT8, &mut buf).unwrap();
    assert_eq!(&buf[4..], &(-128_f64).to_be_bytes());

    i8::from_text(oid::BPCHAR, b"A").unwrap_err();
    u8::from_binary(oid::BPCHAR, &[0x41]).unwrap_err();
    65u8.encode(oid::BPCHAR, &mut Vec::new()).unwrap_err();
}

#[test]
fn char_rejected_by_other_numeric_types() {
    fn assert_rejects_char<T>(value: T, name: &str)
    where
        T: for<'a> FromWireValue<'a> + ToWireValue + std::fmt::Debug,
    {
        let mut buf = Vec::new();
        assert!(
            value.encode(oid::CHAR, &mut buf).is_err(),
            "{} encode",
            name
        );
        assert!(buf.is_empty(), "{} wrote {:?}", name, buf);
        for bytes in [&b""[..], b"A", b"\\377", b"1"] {
            assert!(
                T::from_text(oid::CHAR, bytes).is_err(),
                "{} text {:?}",
                name,
                bytes
            );
        }
        for bytes in [&[][..], &[0x41][..], &[0, 0x41][..]] {
            assert!(
                T::from_binary(oid::CHAR, bytes).is_err(),
                "{} binary {:?}",
                name,
                bytes
            );
        }
    }

    assert_rejects_char(1i16, "i16");
    assert_rejects_char(1i32, "i32");
    assert_rejects_char(1i64, "i64");
    assert_rejects_char(1u16, "u16");
    assert_rejects_char(1u32, "u32");
    assert_rejects_char(1u64, "u64");
    assert_rejects_char(1f32, "f32");
    assert_rejects_char(1f64, "f64");
}
