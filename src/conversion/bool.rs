use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

use super::{FromWireValue, ToWireValue};

impl FromWireValue<'_> for bool {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::BOOL {
            return Err(Error::Decode(format!("cannot decode oid {} as bool", oid)));
        }
        match bytes {
            b"t" | b"true" | b"TRUE" | b"T" | b"1" => Ok(true),
            b"f" | b"false" | b"FALSE" | b"F" | b"0" => Ok(false),
            _ => Err(Error::Decode(format!(
                "invalid boolean: {:?}",
                String::from_utf8_lossy(bytes)
            ))),
        }
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if oid != oid::BOOL {
            return Err(Error::Decode(format!("cannot decode oid {} as bool", oid)));
        }
        if bytes.len() != 1 {
            return Err(Error::Decode(format!(
                "invalid boolean length: {}",
                bytes.len()
            )));
        }
        Ok(bytes[0] != 0)
    }
}

impl ToWireValue for bool {
    const NATURAL_OID: Oid = oid::BOOL;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::BOOL => {
                buf.extend_from_slice(&1_i32.to_be_bytes());
                buf.push(if *self { 1 } else { 0 });
                Ok(())
            }
            _ => Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_text() {
        assert!(bool::from_text(oid::BOOL, b"t").unwrap());
        assert!(bool::from_text(oid::BOOL, b"true").unwrap());
        assert!(!bool::from_text(oid::BOOL, b"f").unwrap());
        assert!(!bool::from_text(oid::BOOL, b"false").unwrap());
    }

    #[test]
    fn bool_binary() {
        assert!(bool::from_binary(oid::BOOL, &[1]).unwrap());
        assert!(!bool::from_binary(oid::BOOL, &[0]).unwrap());
    }
}
