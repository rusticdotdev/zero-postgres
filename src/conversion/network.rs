#[cfg(test)]
#[path = "network_tests.rs"]
mod tests;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

use super::bytes::HEX_LOOKUP;
use super::{FromWireValue, ToWireValue};

// A tag byte for inet and cidr
const IPV4_TAG: u8 = 2;
const IPV6_TAG: u8 = 3;

// ─── MAC Address ─────────────────────────────────────────────────────────────

fn mac_address_from_text<const N: usize>(text: &[u8]) -> Result<[u8; N]> {
    if text.len() != N * 3 - 1 {
        return Err(Error::Decode(format!(
            "invalid MAC address length: {}",
            text.len()
        )));
    }
    let mut address = [0_u8; N];
    for (octet, chunk) in address.iter_mut().zip(text.chunks(3)) {
        let (&[high, low] | &[high, low, b':']) = chunk else {
            return Err(Error::Decode("invalid MAC address separator".into()));
        };
        let high = HEX_LOOKUP[high as usize];
        let low = HEX_LOOKUP[low as usize];
        if (high | low) > 0x0F {
            return Err(Error::Decode("invalid MAC address hex digit".into()));
        }
        *octet = (high << 4) | low;
    }
    Ok(address)
}

macro_rules! impl_mac_address {
    ($oid:ident, $length:literal) => {
        impl FromWireValue<'_> for [u8; $length] {
            fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
                if oid != oid::$oid {
                    return Err(Error::Decode(format!(
                        "cannot decode oid {} as [u8; {}]",
                        oid, $length
                    )));
                }
                mac_address_from_text(bytes)
            }

            fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
                if oid != oid::$oid {
                    return Err(Error::Decode(format!(
                        "cannot decode oid {} as [u8; {}]",
                        oid, $length
                    )));
                }
                bytes.try_into().map_err(|_unhelpful_err| {
                    Error::Decode(format!("invalid MAC address length: {}", bytes.len()))
                })
            }
        }

        impl ToWireValue for [u8; $length] {
            const NATURAL_OID: Oid = oid::$oid;

            fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
                match target_oid {
                    oid::$oid => {
                        buf.extend_from_slice(&($length as i32).to_be_bytes());
                        buf.extend_from_slice(self);
                        Ok(())
                    }
                    _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
                }
            }
        }
    };
}

impl_mac_address!(MACADDR, 6);
impl_mac_address!(MACADDR8, 8);

// ─── IP Address ──────────────────────────────────────────────────────────────

fn max_prefix_length(address: &IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn has_host_bits(address: &IpAddr, prefix_length: u8) -> bool {
    let prefix_length = u32::from(prefix_length);
    match address {
        IpAddr::V4(address) => {
            address.to_bits() & u32::MAX.checked_shr(prefix_length).unwrap_or(0) != 0
        }
        IpAddr::V6(address) => {
            address.to_bits() & u128::MAX.checked_shr(prefix_length).unwrap_or(0) != 0
        }
    }
}

fn inet_from_text(text: &[u8]) -> Result<(IpAddr, u8)> {
    let text = simdutf8::compat::from_utf8(text)
        .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
    let (address, prefix_length) = match text.split_once('/') {
        Some((address, prefix_length)) => (address, Some(prefix_length)),
        None => (text, None),
    };
    let address: IpAddr = address
        .parse()
        .map_err(|e| Error::Decode(format!("invalid IP address: {}", e)))?;
    let prefix_length = match prefix_length {
        Some(prefix_length) => prefix_length
            .parse()
            .map_err(|e| Error::Decode(format!("invalid prefix length: {}", e)))?,
        None => max_prefix_length(&address),
    };
    if prefix_length > max_prefix_length(&address) {
        return Err(Error::Decode(format!(
            "invalid prefix length: {}",
            prefix_length
        )));
    }
    Ok((address, prefix_length))
}

fn inet_from_binary(bytes: &[u8]) -> Result<(IpAddr, u8)> {
    let (address, prefix_length) = match bytes.split_first_chunk::<4>() {
        Some((&[IPV4_TAG, prefix_length, _is_cidr, 4], octets)) => {
            let octets: [u8; 4] = octets.try_into().map_err(|_unhelpful_err| {
                Error::Decode(format!("invalid IP address length: {}", octets.len()))
            })?;
            (IpAddr::V4(Ipv4Addr::from(octets)), prefix_length)
        }
        Some((&[IPV6_TAG, prefix_length, _is_cidr, 16], octets)) => {
            let octets: [u8; 16] = octets.try_into().map_err(|_unhelpful_err| {
                Error::Decode(format!("invalid IP address length: {}", octets.len()))
            })?;
            (IpAddr::V6(Ipv6Addr::from(octets)), prefix_length)
        }
        _ => return Err(Error::Decode("invalid IP address".into())),
    };
    if prefix_length > max_prefix_length(&address) {
        return Err(Error::Decode(format!(
            "invalid prefix length: {}",
            prefix_length
        )));
    }
    Ok((address, prefix_length))
}

impl FromWireValue<'_> for (IpAddr, u8) {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        match oid {
            oid::INET | oid::CIDR => inet_from_text(bytes),
            _ => Err(Error::Decode(format!(
                "cannot decode oid {} as (IpAddr, u8)",
                oid
            ))),
        }
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        match oid {
            oid::INET | oid::CIDR => inet_from_binary(bytes),
            _ => Err(Error::Decode(format!(
                "cannot decode oid {} as (IpAddr, u8)",
                oid
            ))),
        }
    }
}

impl ToWireValue for (IpAddr, u8) {
    const NATURAL_OID: Oid = oid::INET;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        let (address, prefix_length) = *self;
        if !matches!(target_oid, oid::INET | oid::CIDR) {
            return Err(Error::type_mismatch(Self::NATURAL_OID, target_oid));
        }
        if prefix_length > max_prefix_length(&address) {
            return Err(Error::Encode(format!(
                "invalid prefix length {} for {}",
                prefix_length, address
            )));
        }
        let is_cidr = target_oid == oid::CIDR;
        if is_cidr && has_host_bits(&address, prefix_length) {
            return Err(Error::Encode(format!(
                "cidr {}/{} has bits set to right of prefix",
                address, prefix_length
            )));
        }
        match address {
            IpAddr::V4(address) => {
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&[IPV4_TAG, prefix_length, u8::from(is_cidr), 4]);
                buf.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                buf.extend_from_slice(&20_i32.to_be_bytes());
                buf.extend_from_slice(&[IPV6_TAG, prefix_length, u8::from(is_cidr), 16]);
                buf.extend_from_slice(&address.octets());
            }
        }
        Ok(())
    }
}
