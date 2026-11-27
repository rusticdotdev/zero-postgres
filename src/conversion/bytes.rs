//! Byte type implementations (`&[u8]`, `Vec<u8>`).

#[cfg(test)]
#[path = "bytes_tests.rs"]
mod tests;

use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

use super::{FromWireValue, ToWireValue};

impl<'a> FromWireValue<'a> for &'a [u8] {
    fn from_text(oid: Oid, bytes: &'a [u8]) -> Result<Self> {
        if oid != oid::BYTEA {
            return Err(Error::Decode(format!("cannot decode oid {} as bytes", oid)));
        }
        match memchr::memchr(b'\\', bytes) {
            None => Ok(bytes),
            Some(0) if bytes == b"\\x" => Ok(&bytes[2..]),
            Some(_) => Err(Error::Decode(
                "cannot borrow bytea in text format as bytes; decode as Vec<u8>".into(),
            )),
        }
    }

    fn from_binary(oid: Oid, bytes: &'a [u8]) -> Result<Self> {
        if oid != oid::BYTEA {
            return Err(Error::Decode(format!("cannot decode oid {} as bytes", oid)));
        }
        Ok(bytes)
    }
}

impl FromWireValue<'_> for Vec<u8> {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::BYTEA {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Vec<u8>",
                oid
            )));
        }
        if bytes.starts_with(b"\\x") {
            decode_hex(&bytes[2..])
        } else {
            decode_escape(bytes)
        }
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::BYTEA {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as Vec<u8>",
                oid
            )));
        }
        Ok(bytes.to_vec())
    }
}

impl ToWireValue for [u8] {
    const NATURAL_OID: Oid = oid::BYTEA;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::BYTEA => {
                buf.extend_from_slice(&(self.len() as i32).to_be_bytes());
                buf.extend_from_slice(self);
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl ToWireValue for Vec<u8> {
    const NATURAL_OID: Oid = oid::BYTEA;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        self.as_slice().encode(target_oid, buf)
    }
}

/// Nibble lookup table: ASCII byte → 0x00–0x0F for valid hex, 0xFF for invalid.
static HEX_LOOKUP: [u8; 256] = {
    let mut table = [0xFF_u8; 256];
    let mut i: usize = 0;
    while i < 256 {
        table[i] = match i as u8 {
            b'0'..=b'9' => i as u8 - b'0',
            b'a'..=b'f' => i as u8 - b'a' + 10,
            b'A'..=b'F' => i as u8 - b'A' + 10,
            _ => 0xFF,
        };
        i += 1;
    }
    table
};

/// Decode hex string to bytes
fn decode_hex(hex: &[u8]) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Decode("invalid hex length".into()));
    }

    let mut result = Vec::with_capacity(hex.len() >> 1);
    for &[hi, lo] in hex.as_chunks::<2>().0 {
        let high = HEX_LOOKUP[hi as usize];
        let low = HEX_LOOKUP[lo as usize];
        if (high | low) > 0x0F {
            return Err(Error::Decode("invalid hex digit".into()));
        }
        result.push((high << 4) | low);
    }
    Ok(result)
}

fn decode_escape(text: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = memchr::memchr(b'\\', rest) {
        result.extend_from_slice(&rest[..position]);
        match rest[position + 1..] {
            [b'\\', ..] => {
                result.push(b'\\');
                rest = &rest[position + 2..];
            }
            [
                high @ b'0'..=b'3',
                middle @ b'0'..=b'7',
                low @ b'0'..=b'7',
                ..,
            ] => {
                result.push(((high - b'0') << 6) | ((middle - b'0') << 3) | (low - b'0'));
                rest = &rest[position + 4..];
            }
            _ => return Err(Error::Decode("invalid bytea escape".into())),
        }
    }
    result.extend_from_slice(rest);
    Ok(result)
}
