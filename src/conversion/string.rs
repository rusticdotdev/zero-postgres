//! String type implementations (&str, String).

#[cfg(test)]
#[path = "string_tests.rs"]
mod tests;

use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

use super::{FromWireValue, ToWireValue};

const JSONB_VERSION: u8 = 1;
const JSONPATH_VERSION: u8 = 1;

impl<'a> FromWireValue<'a> for &'a str {
    fn from_text(oid: Oid, bytes: &'a [u8]) -> Result<Self> {
        // NUMERIC uses text format, so it can be decoded as str in text mode
        if !matches!(
            oid,
            oid::TEXT
                | oid::VARCHAR
                | oid::BPCHAR
                | oid::NAME
                | oid::JSON
                | oid::JSONB
                | oid::JSONPATH
                | oid::NUMERIC
        ) {
            return Err(Error::Decode(format!("cannot decode oid {} as str", oid)));
        }
        simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &'a [u8]) -> Result<Self> {
        match (oid, bytes.split_first()) {
            (oid::JSONB, Some((&JSONB_VERSION, text)))
            | (oid::JSONPATH, Some((&JSONPATH_VERSION, text))) => {
                return Self::from_binary(oid::TEXT, text);
            }
            (oid::JSONB | oid::JSONPATH, _) => {
                return Err(Error::Decode(format!(
                    "unsupported binary version for oid {}",
                    oid
                )));
            }
            _ => {}
        }
        // Note: NUMERIC binary format is NOT UTF-8, so we don't accept it here
        if !matches!(
            oid,
            oid::TEXT | oid::VARCHAR | oid::BPCHAR | oid::NAME | oid::JSON
        ) {
            return Err(Error::Decode(format!("cannot decode oid {} as str", oid)));
        }
        simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))
    }
}

impl FromWireValue<'_> for String {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        // NUMERIC uses text format, so it can be decoded as String in text mode
        if !matches!(
            oid,
            oid::TEXT
                | oid::VARCHAR
                | oid::BPCHAR
                | oid::NAME
                | oid::JSON
                | oid::JSONB
                | oid::JSONPATH
                | oid::NUMERIC
        ) {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as String",
                oid
            )));
        }
        simdutf8::compat::from_utf8(bytes)
            .map(|s| s.to_owned())
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        match (oid, bytes.split_first()) {
            (oid::JSONB, Some((&JSONB_VERSION, text)))
            | (oid::JSONPATH, Some((&JSONPATH_VERSION, text))) => {
                return Self::from_binary(oid::TEXT, text);
            }
            (oid::JSONB | oid::JSONPATH, _) => {
                return Err(Error::Decode(format!(
                    "unsupported binary version for oid {}",
                    oid
                )));
            }
            _ => {}
        }
        // Note: NUMERIC binary format is NOT UTF-8, so we don't accept it here
        if !matches!(
            oid,
            oid::TEXT | oid::VARCHAR | oid::BPCHAR | oid::NAME | oid::JSON
        ) {
            return Err(Error::Decode(format!(
                "cannot decode oid {} as String",
                oid
            )));
        }
        simdutf8::compat::from_utf8(bytes)
            .map(|s| s.to_owned())
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))
    }
}

impl ToWireValue for str {
    const NATURAL_OID: Oid = oid::TEXT;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::TEXT | oid::VARCHAR | oid::BPCHAR | oid::NAME | oid::JSON => {
                let bytes = self.as_bytes();
                buf.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                buf.extend_from_slice(bytes);
                Ok(())
            }
            oid::JSONB => encode_with_version(JSONB_VERSION, self, buf),
            oid::JSONPATH => encode_with_version(JSONPATH_VERSION, self, buf),
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

impl ToWireValue for String {
    const NATURAL_OID: Oid = oid::TEXT;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        self.as_str().encode(target_oid, buf)
    }
}

fn encode_with_version(version: u8, text: &str, buf: &mut Vec<u8>) -> Result<()> {
    let bytes = text.as_bytes();
    buf.extend_from_slice(&((bytes.len() + 1) as i32).to_be_bytes());
    buf.push(version);
    buf.extend_from_slice(bytes);
    Ok(())
}
