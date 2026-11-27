use super::*;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MACADDR: [u8; 6] = [0x08, 0x00, 0x2b, 0x01, 0x02, 0x03];
const MACADDR8: [u8; 8] = [0x08, 0x00, 0x2b, 0x01, 0x02, 0x03, 0x04, 0x05];

#[test]
fn macaddr_text() {
    assert_eq!(
        <[u8; 6]>::from_text(oid::MACADDR, b"08:00:2b:01:02:03").unwrap(),
        MACADDR
    );
    assert_eq!(
        <[u8; 6]>::from_text(oid::MACADDR, b"FF:ff:00:aB:Cd:9e").unwrap(),
        [0xff, 0xff, 0x00, 0xab, 0xcd, 0x9e]
    );
}

#[test]
fn macaddr8_text() {
    assert_eq!(
        <[u8; 8]>::from_text(oid::MACADDR8, b"08:00:2b:01:02:03:04:05").unwrap(),
        MACADDR8
    );
}

#[test]
fn macaddr_text_invalid() {
    <[u8; 6]>::from_text(oid::MACADDR, b"").unwrap_err();
    <[u8; 6]>::from_text(oid::MACADDR, b"08:00:2b:01:02").unwrap_err();
    <[u8; 6]>::from_text(oid::MACADDR, b"08:00:2b:01:02:03:04:05").unwrap_err();
    <[u8; 6]>::from_text(oid::MACADDR, b"08-00-2b-01-02-03").unwrap_err();
    <[u8; 6]>::from_text(oid::MACADDR, b"08002b:01:02:0304").unwrap_err();
    <[u8; 6]>::from_text(oid::MACADDR, b"08:00:2g:01:02:03").unwrap_err();
    <[u8; 6]>::from_text(oid::MACADDR, b"08:00:2b:01:02:0:").unwrap_err();
    <[u8; 8]>::from_text(oid::MACADDR8, b"08:00:2b:01:02:03").unwrap_err();
}

#[test]
fn macaddr_binary() {
    assert_eq!(
        <[u8; 6]>::from_binary(oid::MACADDR, &MACADDR).unwrap(),
        MACADDR
    );
    assert_eq!(
        <[u8; 8]>::from_binary(oid::MACADDR8, &MACADDR8).unwrap(),
        MACADDR8
    );
    <[u8; 6]>::from_binary(oid::MACADDR, &MACADDR8).unwrap_err();
    <[u8; 8]>::from_binary(oid::MACADDR8, &MACADDR).unwrap_err();
}

#[test]
fn macaddr_oid_mismatch() {
    <[u8; 6]>::from_text(oid::MACADDR8, b"08:00:2b:01:02:03").unwrap_err();
    <[u8; 6]>::from_binary(oid::BYTEA, &MACADDR).unwrap_err();
    <[u8; 8]>::from_text(oid::MACADDR, b"08:00:2b:01:02:03:04:05").unwrap_err();
    <[u8; 8]>::from_binary(oid::BYTEA, &MACADDR8).unwrap_err();
}

#[test]
fn macaddr_encode() {
    let mut buf = Vec::new();
    MACADDR.encode(oid::MACADDR, &mut buf).unwrap();
    assert_eq!(buf[..4], 6_i32.to_be_bytes());
    assert_eq!(buf[4..], MACADDR);

    buf.clear();
    MACADDR8.encode(oid::MACADDR8, &mut buf).unwrap();
    assert_eq!(buf[..4], 8_i32.to_be_bytes());
    assert_eq!(buf[4..], MACADDR8);
}

#[test]
fn macaddr_encode_oid_mismatch() {
    let mut buf = Vec::new();
    MACADDR.encode(oid::MACADDR8, &mut buf).unwrap_err();
    MACADDR.encode(oid::BYTEA, &mut buf).unwrap_err();
    MACADDR8.encode(oid::MACADDR, &mut buf).unwrap_err();
    assert!(buf.is_empty());
}

#[test]
fn macaddr_natural_oid() {
    assert_eq!(<[u8; 6]>::NATURAL_OID, oid::MACADDR);
    assert_eq!(<[u8; 8]>::NATURAL_OID, oid::MACADDR8);
}

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn ipv6(text: &str) -> IpAddr {
    IpAddr::V6(text.parse::<Ipv6Addr>().unwrap())
}

#[test]
fn inet_text() {
    assert_eq!(
        <(IpAddr, u8)>::from_text(oid::INET, b"192.168.1.5/24").unwrap(),
        (ipv4(192, 168, 1, 5), 24)
    );
    assert_eq!(
        <(IpAddr, u8)>::from_text(oid::INET, b"192.168.1.5").unwrap(),
        (ipv4(192, 168, 1, 5), 32)
    );
    assert_eq!(
        <(IpAddr, u8)>::from_text(oid::INET, b"0.0.0.0/0").unwrap(),
        (ipv4(0, 0, 0, 0), 0)
    );
    assert_eq!(
        <(IpAddr, u8)>::from_text(oid::INET, b"::1").unwrap(),
        (ipv6("::1"), 128)
    );
    assert_eq!(
        <(IpAddr, u8)>::from_text(oid::INET, b"2001:db8::1/64").unwrap(),
        (ipv6("2001:db8::1"), 64)
    );
    assert_eq!(
        <(IpAddr, u8)>::from_text(oid::INET, b"::ffff:1.2.3.4").unwrap(),
        (ipv6("::ffff:102:304"), 128)
    );
}

#[test]
fn cidr_text() {
    assert_eq!(
        <(IpAddr, u8)>::from_text(oid::CIDR, b"192.168.1.0/24").unwrap(),
        (ipv4(192, 168, 1, 0), 24)
    );
    assert_eq!(
        <(IpAddr, u8)>::from_text(oid::CIDR, b"2001:db8::/32").unwrap(),
        (ipv6("2001:db8::"), 32)
    );
}

#[test]
fn inet_text_invalid() {
    <(IpAddr, u8)>::from_text(oid::INET, b"").unwrap_err();
    <(IpAddr, u8)>::from_text(oid::INET, b"192.168.1/24").unwrap_err();
    <(IpAddr, u8)>::from_text(oid::INET, b"192.168.1.5/33").unwrap_err();
    <(IpAddr, u8)>::from_text(oid::INET, b"192.168.1.5/").unwrap_err();
    <(IpAddr, u8)>::from_text(oid::INET, b"192.168.1.5/-1").unwrap_err();
    <(IpAddr, u8)>::from_text(oid::INET, b"::1/129").unwrap_err();
    <(IpAddr, u8)>::from_text(oid::INET, b"::1/256").unwrap_err();
    <(IpAddr, u8)>::from_text(oid::TEXT, b"192.168.1.5").unwrap_err();
}

#[test]
fn inet_binary() {
    assert_eq!(
        <(IpAddr, u8)>::from_binary(oid::INET, &[2, 24, 0, 4, 192, 168, 1, 5]).unwrap(),
        (ipv4(192, 168, 1, 5), 24)
    );
    assert_eq!(
        <(IpAddr, u8)>::from_binary(oid::CIDR, &[2, 24, 1, 4, 192, 168, 1, 0]).unwrap(),
        (ipv4(192, 168, 1, 0), 24)
    );
    let mut bytes = vec![3, 64, 0, 16];
    bytes.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    assert_eq!(
        <(IpAddr, u8)>::from_binary(oid::INET, &bytes).unwrap(),
        (ipv6("2001:db8::1"), 64)
    );
}

#[test]
fn inet_binary_invalid() {
    <(IpAddr, u8)>::from_binary(oid::INET, &[]).unwrap_err();
    <(IpAddr, u8)>::from_binary(oid::INET, &[1, 24, 0, 4, 192, 168, 1, 5]).unwrap_err();
    <(IpAddr, u8)>::from_binary(oid::INET, &[2, 33, 0, 4, 192, 168, 1, 5]).unwrap_err();
    <(IpAddr, u8)>::from_binary(oid::INET, &[2, 24, 0, 4, 192, 168, 1]).unwrap_err();
    <(IpAddr, u8)>::from_binary(oid::INET, &[2, 24, 0, 4, 192, 168, 1, 5, 0]).unwrap_err();
    <(IpAddr, u8)>::from_binary(oid::INET, &[2, 24, 0, 16, 192, 168, 1, 5]).unwrap_err();
    <(IpAddr, u8)>::from_binary(oid::INET, &[3, 64, 0, 16, 0, 0, 0, 0]).unwrap_err();
    let mut bytes = vec![3, 129, 0, 16];
    bytes.extend_from_slice(&[0; 16]);
    <(IpAddr, u8)>::from_binary(oid::INET, &bytes).unwrap_err();
    <(IpAddr, u8)>::from_binary(oid::BYTEA, &[2, 24, 0, 4, 192, 168, 1, 5]).unwrap_err();
}

#[test]
fn inet_encode() {
    let mut buf = Vec::new();
    (ipv4(192, 168, 1, 5), 24_u8)
        .encode(oid::INET, &mut buf)
        .unwrap();
    assert_eq!(buf[..4], 8_i32.to_be_bytes());
    assert_eq!(buf[4..], [2, 24, 0, 4, 192, 168, 1, 5]);

    buf.clear();
    (ipv6("2001:db8::1"), 64_u8)
        .encode(oid::INET, &mut buf)
        .unwrap();
    assert_eq!(buf[..4], 20_i32.to_be_bytes());
    assert_eq!(buf[4..8], [3, 64, 0, 16]);
    assert_eq!(
        buf[8..],
        "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
    );
}

#[test]
fn cidr_encode() {
    let mut buf = Vec::new();
    (ipv4(192, 168, 1, 0), 24_u8)
        .encode(oid::CIDR, &mut buf)
        .unwrap();
    assert_eq!(buf[4..], [2, 24, 1, 4, 192, 168, 1, 0]);

    buf.clear();
    (ipv4(192, 168, 1, 5), 32_u8)
        .encode(oid::CIDR, &mut buf)
        .unwrap();
    assert_eq!(buf[4..], [2, 32, 1, 4, 192, 168, 1, 5]);

    buf.clear();
    (ipv4(0, 0, 0, 0), 0_u8)
        .encode(oid::CIDR, &mut buf)
        .unwrap();
    assert_eq!(buf[4..], [2, 0, 1, 4, 0, 0, 0, 0]);

    buf.clear();
    (ipv6("2001:db8::"), 32_u8)
        .encode(oid::CIDR, &mut buf)
        .unwrap();
    assert_eq!(buf[4..8], [3, 32, 1, 16]);
}

#[test]
fn cidr_encode_host_bits() {
    let mut buf = Vec::new();
    (ipv4(192, 168, 1, 5), 24_u8)
        .encode(oid::CIDR, &mut buf)
        .unwrap_err();
    (ipv4(0, 0, 0, 1), 0_u8)
        .encode(oid::CIDR, &mut buf)
        .unwrap_err();
    (ipv6("2001:db8::1"), 64_u8)
        .encode(oid::CIDR, &mut buf)
        .unwrap_err();
    (ipv6("::1"), 127_u8)
        .encode(oid::CIDR, &mut buf)
        .unwrap_err();
    assert!(buf.is_empty());
}

#[test]
fn inet_encode_invalid() {
    let mut buf = Vec::new();
    (ipv4(192, 168, 1, 5), 33_u8)
        .encode(oid::INET, &mut buf)
        .unwrap_err();
    (ipv6("::1"), 129_u8)
        .encode(oid::INET, &mut buf)
        .unwrap_err();
    (ipv4(192, 168, 1, 5), 24_u8)
        .encode(oid::TEXT, &mut buf)
        .unwrap_err();
    assert!(buf.is_empty());
}

#[test]
fn inet_roundtrip() {
    for value in [
        (ipv4(10, 1, 2, 3), 8_u8),
        (ipv4(255, 255, 255, 255), 32),
        (ipv6("fe80::1"), 10),
        (ipv6("::"), 0),
    ] {
        let mut buf = Vec::new();
        value.encode(oid::INET, &mut buf).unwrap();
        assert_eq!(
            <(IpAddr, u8)>::from_binary(oid::INET, &buf[4..]).unwrap(),
            value
        );
    }
}

#[test]
fn inet_natural_oid() {
    assert_eq!(<(IpAddr, u8)>::NATURAL_OID, oid::INET);
}
