use super::*;

#[test]
fn string_text() {
    assert_eq!(String::from_text(oid::TEXT, b"hello").unwrap(), "hello");
}

#[test]
fn type_mismatch() {
    // Trying to decode INT4 as String should fail
    String::from_binary(oid::INT4, &[0, 0, 0, 1]).unwrap_err();
}

#[test]
fn encode_jsonb_prefixes_version() {
    let mut buf = Vec::new();
    "{}".encode(oid::JSONB, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 3, 1, b'{', b'}']);
}

#[test]
fn encode_json_has_no_version() {
    let mut buf = Vec::new();
    "{}".encode(oid::JSON, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 2, b'{', b'}']);
}

#[test]
fn json_decode() {
    let json = br#"{"a": [1, 2], "b": "\u00e9"}"#;
    assert_eq!(<&str>::from_text(oid::JSON, json).unwrap().as_bytes(), json);
    assert_eq!(
        <&str>::from_binary(oid::JSON, json).unwrap().as_bytes(),
        json
    );
    assert_eq!(String::from_text(oid::JSON, json).unwrap().as_bytes(), json);
    assert_eq!(
        String::from_binary(oid::JSON, json).unwrap().as_bytes(),
        json
    );
}

#[test]
fn json_decode_invalid_utf8() {
    <&str>::from_binary(oid::JSON, &[b'"', 0xff, b'"']).unwrap_err();
    String::from_text(oid::JSON, &[b'"', 0xff, b'"']).unwrap_err();
}

#[test]
fn jsonb_decode() {
    assert_eq!(<&str>::from_text(oid::JSONB, b"{}").unwrap(), "{}");
    assert_eq!(String::from_text(oid::JSONB, b"{}").unwrap(), "{}");
    assert_eq!(<&str>::from_binary(oid::JSONB, b"\x01{}").unwrap(), "{}");
    assert_eq!(String::from_binary(oid::JSONB, b"\x01{}").unwrap(), "{}");
    assert_eq!(<&str>::from_binary(oid::JSONB, b"\x01").unwrap(), "");
}

#[test]
fn jsonb_decode_unsupported_version() {
    <&str>::from_binary(oid::JSONB, b"").unwrap_err();
    <&str>::from_binary(oid::JSONB, b"{}").unwrap_err();
    <&str>::from_binary(oid::JSONB, b"\x02{}").unwrap_err();
    String::from_binary(oid::JSONB, b"").unwrap_err();
    String::from_binary(oid::JSONB, b"\x00{}").unwrap_err();
}

#[test]
fn jsonb_round_trip() {
    let mut buf = Vec::new();
    "{\"a\": 1}".encode(oid::JSONB, &mut buf).unwrap();
    assert_eq!(
        <&str>::from_binary(oid::JSONB, &buf[4..]).unwrap(),
        "{\"a\": 1}"
    );
}

#[test]
fn jsonpath_decode() {
    assert_eq!(
        <&str>::from_text(oid::JSONPATH, b"$.a[*]").unwrap(),
        "$.a[*]"
    );
    assert_eq!(
        String::from_text(oid::JSONPATH, b"$.a[*]").unwrap(),
        "$.a[*]"
    );
    assert_eq!(
        <&str>::from_binary(oid::JSONPATH, b"\x01$.a[*]").unwrap(),
        "$.a[*]"
    );
    assert_eq!(
        String::from_binary(oid::JSONPATH, b"\x01$.a[*]").unwrap(),
        "$.a[*]"
    );
}

#[test]
fn jsonpath_decode_unsupported_version() {
    <&str>::from_binary(oid::JSONPATH, b"").unwrap_err();
    <&str>::from_binary(oid::JSONPATH, b"$.a").unwrap_err();
    String::from_binary(oid::JSONPATH, b"\x02$.a").unwrap_err();
}

#[test]
fn jsonpath_encode() {
    let mut buf = Vec::new();
    "$.a".encode(oid::JSONPATH, &mut buf).unwrap();
    assert_eq!(buf, [0, 0, 0, 4, 1, b'$', b'.', b'a']);

    let mut owned = Vec::new();
    String::from("$.a")
        .encode(oid::JSONPATH, &mut owned)
        .unwrap();
    assert_eq!(owned, buf);
    assert_eq!(
        <&str>::from_binary(oid::JSONPATH, &buf[4..]).unwrap(),
        "$.a"
    );
}
