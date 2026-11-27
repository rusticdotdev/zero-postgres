use super::*;

#[test]
fn bytea_hex() {
    assert_eq!(
        Vec::<u8>::from_text(oid::BYTEA, b"\\xDEADBEEF").unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
}

#[test]
fn bytea_hex_as_slice() {
    let decoded = <&[u8]>::from_text(oid::BYTEA, b"\\xDEADBEEF");
    assert!(
        matches!(decoded, Err(_) | Ok([0xDE, 0xAD, 0xBE, 0xEF])),
        "{decoded:?}"
    );
}

#[test]
fn bytea_empty_hex_as_slice() {
    assert_eq!(<&[u8]>::from_text(oid::BYTEA, b"\\x").unwrap(), b"");
}

#[test]
fn bytea_escape_as_slice() {
    assert_eq!(<&[u8]>::from_text(oid::BYTEA, b"").unwrap(), b"");
    assert_eq!(
        <&[u8]>::from_text(oid::BYTEA, b"abc 123").unwrap(),
        b"abc 123"
    );
    <&[u8]>::from_text(oid::BYTEA, b"abc\\000def").unwrap_err();
    <&[u8]>::from_text(oid::BYTEA, b"a\\\\b").unwrap_err();
}

#[test]
fn bytea_escape() {
    assert_eq!(Vec::<u8>::from_text(oid::BYTEA, b"").unwrap(), b"");
    assert_eq!(
        Vec::<u8>::from_text(oid::BYTEA, b"abc 123").unwrap(),
        b"abc 123"
    );
    assert_eq!(
        Vec::<u8>::from_text(oid::BYTEA, b"a\\000\\\\b").unwrap(),
        [0x61, 0x00, 0x5c, 0x62]
    );
    assert_eq!(
        Vec::<u8>::from_text(oid::BYTEA, b"\\377\\200\\037~").unwrap(),
        [0xff, 0x80, 0x1f, 0x7e]
    );
    assert_eq!(
        Vec::<u8>::from_text(oid::BYTEA, b"\\\\x41").unwrap(),
        b"\\x41"
    );
}

#[test]
fn bytea_escape_malformed() {
    Vec::<u8>::from_text(oid::BYTEA, b"abc\\").unwrap_err();
    Vec::<u8>::from_text(oid::BYTEA, b"\\12").unwrap_err();
    Vec::<u8>::from_text(oid::BYTEA, b"\\400").unwrap_err();
    Vec::<u8>::from_text(oid::BYTEA, b"\\128").unwrap_err();
    Vec::<u8>::from_text(oid::BYTEA, b"\\n").unwrap_err();
}

#[test]
fn bytea_escape_all_bytes() {
    let original: Vec<u8> = (0..=u8::MAX).collect();
    let mut text = Vec::new();
    for &byte in &original {
        match byte {
            b'\\' => text.extend_from_slice(b"\\\\"),
            0x20..=0x7e => text.push(byte),
            _ => text.extend_from_slice(format!("\\{byte:03o}").as_bytes()),
        }
    }
    assert_eq!(Vec::<u8>::from_text(oid::BYTEA, &text).unwrap(), original);
}
