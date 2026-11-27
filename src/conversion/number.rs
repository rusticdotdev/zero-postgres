#[cfg(test)]
#[path = "number_tests.rs"]
mod tests;

use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

use super::numeric_util::{numeric_to_f32, numeric_to_f64};
use super::{FromWireValue, ToWireValue};

// === Integer types ===

macro_rules! wire_type {
    (INT2) => {
        i16
    };
    (INT4) => {
        i32
    };
    (INT8) => {
        i64
    };
    (FLOAT4) => {
        f32
    };
    (FLOAT8) => {
        f64
    };
}

macro_rules! read_wire {
    ($pg:ident, $bytes:expr) => {{
        type Wire = wire_type!($pg);
        let array: [u8; size_of::<Wire>()] = $bytes.try_into().map_err(|_unhelpful_err| {
            Error::Decode(format!(
                "invalid {} length: {}",
                stringify!($pg),
                $bytes.len()
            ))
        })?;
        Wire::from_be_bytes(array)
    }};
}

macro_rules! read_integer_checked {
    ($rust:ident, $pg:ident, $bytes:expr) => {{
        let value = read_wire!($pg, $bytes);
        <$rust>::try_from(value).map_err(|_unhelpful_err| {
            Error::Decode(format!("value {} overflows {}", value, stringify!($rust)))
        })
    }};
}

macro_rules! write_wire {
    ($pg:ident, $value:expr, $buf:expr) => {{
        type Wire = wire_type!($pg);
        let value: Wire = $value;
        $buf.extend_from_slice(&(size_of::<Wire>() as i32).to_be_bytes());
        $buf.extend_from_slice(&value.to_be_bytes());
    }};
}

macro_rules! write_integer_checked {
    ($rust:ident, $pg:ident, $value:expr, $buf:expr) => {
        write_wire!(
            $pg,
            $value
                .try_into()
                .map_err(|_unhelpful_err| Error::overflow(stringify!($rust), stringify!($pg)))?,
            $buf
        )
    };
}

macro_rules! exact_float {
    ($integer:ident => $float:ident, $value:expr) => {{
        let value: $integer = $value;
        let magnitude = value.abs_diff(0);
        let unused_bits = magnitude.leading_zeros() + magnitude.trailing_zeros();
        (<$integer>::BITS.saturating_sub(unused_bits) <= <$float>::MANTISSA_DIGITS)
            .then_some(value as $float)
    }};
}

macro_rules! read_integer_as_float_checked {
    ($rust:ident, $pg:ident, $bytes:expr) => {{
        type Integer = wire_type!($pg);
        let value = read_wire!($pg, $bytes);
        exact_float!(Integer => $rust, value).ok_or_else(|| {
            Error::Decode(format!(
                "value {} is not exactly representable as {}",
                value,
                stringify!($rust)
            ))
        })
    }};
}

macro_rules! parse_integer_as_float_checked {
    ($rust:ident, $bytes:expr) => {{
        let s = simdutf8::compat::from_utf8($bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
        let value: i64 = s
            .parse()
            .map_err(|e| Error::Decode(format!("invalid integer: {}", e)))?;
        exact_float!(i64 => $rust, value).ok_or_else(|| {
            Error::Decode(format!(
                "value {} is not exactly representable as {}",
                value,
                stringify!($rust)
            ))
        })
    }};
}

macro_rules! write_integer_as_float_checked {
    ($rust:ident, $pg:ident, $value:expr, $buf:expr) => {{
        type Float = wire_type!($pg);
        let value: $rust = $value;
        let float = exact_float!($rust => Float, value).ok_or_else(|| {
            Error::Encode(format!(
                "value {} is not exactly representable as {}",
                value,
                stringify!($pg)
            ))
        })?;
        write_wire!($pg, float, $buf)
    }};
}

fn char_from_text(bytes: &[u8]) -> Result<u8> {
    match *bytes {
        [] => Ok(0),
        [byte @ 0x01..=0x7F] => Ok(byte),
        [
            b'\\',
            high @ b'2'..=b'3',
            middle @ b'0'..=b'7',
            low @ b'0'..=b'7',
        ] => Ok(((high - b'0') << 6) | ((middle - b'0') << 3) | (low - b'0')),
        _ => Err(Error::Decode(format!(
            "invalid \"char\": {:?}",
            String::from_utf8_lossy(bytes)
        ))),
    }
}

macro_rules! impl_integer {
    (
        rust: $rust:ident,
        natural: $natural:ident,
        smaller_types: [$($smaller_types:ident),*],
        exact_types: [$($exact_types:ident),*],
        larger_types: [$($larger_types:ident),*],
        similar_types: [$($similar_types:ident),*],
        larger_float_types: [$($larger_float_types:ident),*],
        similar_float_types: [$($similar_float_types:ident),*],
        byte_types: [$($byte_types:ident),*] $(,)?
    ) => {
        impl FromWireValue<'_> for $rust {
            fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
                $(if oid == oid::$byte_types {
                    return Ok(Self::from_be_bytes([char_from_text(bytes)?]));
                })*
                match oid {
                    $(| oid::$smaller_types)* $(| oid::$exact_types)* $(| oid::$larger_types)* $(| oid::$similar_types)* => {}
                    _ => {
                        return Err(Error::Decode(format!(
                            "cannot decode oid {} as {}",
                            oid,
                            stringify!($rust)
                        )));
                    }
                }
                let s = simdutf8::compat::from_utf8(bytes)
                    .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;
                s.parse().map_err(|e| {
                    Error::Decode(format!("invalid {}: {}", stringify!($rust), e))
                })
            }

            fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
                match oid {
                    $(oid::$smaller_types => Ok(Self::from(read_wire!($smaller_types, bytes))),)*
                    $(oid::$exact_types => Ok(read_wire!($exact_types, bytes)),)*
                    $(oid::$larger_types => read_integer_checked!($rust, $larger_types, bytes),)*
                    $(oid::$similar_types => read_integer_checked!($rust, $similar_types, bytes),)*
                    $(oid::$byte_types => {
                        let array: [u8; size_of::<$rust>()] = bytes.try_into().map_err(|_unhelpful_err| {
                            Error::Decode(format!(
                                "invalid {} length: {}",
                                stringify!($byte_types),
                                bytes.len()
                            ))
                        })?;
                        Ok(Self::from_be_bytes(array))
                    })*
                    _ => Err(Error::Decode(format!(
                        "cannot decode oid {} as {}",
                        oid,
                        stringify!($rust)
                    ))),
                }
            }
        }

        impl ToWireValue for $rust {
            const NATURAL_OID: Oid = oid::$natural;

            fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
                match target_oid {
                    $(oid::$smaller_types => write_integer_checked!($rust, $smaller_types, (*self), buf),)*
                    $(oid::$exact_types => write_wire!($exact_types, *self, buf),)*
                    $(oid::$larger_types => write_wire!($larger_types, (*self).into(), buf),)*
                    $(oid::$similar_types => write_integer_checked!($rust, $similar_types, (*self), buf),)*
                    $(oid::$larger_float_types => write_wire!($larger_float_types, (*self).into(), buf),)*
                    $(oid::$similar_float_types => write_integer_as_float_checked!($rust, $similar_float_types, *self, buf),)*
                    $(oid::$byte_types => {
                        buf.extend_from_slice(&(size_of::<$rust>() as i32).to_be_bytes());
                        buf.extend_from_slice(&self.to_be_bytes());
                    })*
                    _ => return Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
                }
                Ok(())
            }
        }
    };
}

impl_integer! {
    rust: i8,
    natural: INT2,
    smaller_types: [],
    exact_types: [],
    larger_types: [INT2, INT4, INT8],
    similar_types: [],
    larger_float_types: [FLOAT4, FLOAT8],
    similar_float_types: [],
    byte_types: [CHAR],
}

impl_integer! {
    rust: i16,
    natural: INT2,
    smaller_types: [],
    exact_types: [INT2],
    larger_types: [INT4, INT8],
    similar_types: [],
    larger_float_types: [FLOAT4, FLOAT8],
    similar_float_types: [],
    byte_types: [],
}

impl_integer! {
    rust: i32,
    natural: INT4,
    smaller_types: [INT2],
    exact_types: [INT4],
    larger_types: [INT8],
    similar_types: [],
    larger_float_types: [FLOAT8],
    similar_float_types: [FLOAT4],
    byte_types: [],
}

impl_integer! {
    rust: i64,
    natural: INT8,
    smaller_types: [INT2, INT4],
    exact_types: [INT8],
    larger_types: [],
    similar_types: [],
    larger_float_types: [],
    similar_float_types: [FLOAT4, FLOAT8],
    byte_types: [],
}

impl_integer! {
    rust: u8,
    natural: INT2,
    smaller_types: [],
    exact_types: [],
    larger_types: [INT2, INT4, INT8],
    similar_types: [],
    larger_float_types: [FLOAT4, FLOAT8],
    similar_float_types: [],
    byte_types: [CHAR],
}

impl_integer! {
    rust: u16,
    natural: INT4,
    smaller_types: [],
    exact_types: [],
    larger_types: [INT4, INT8],
    similar_types: [INT2],
    larger_float_types: [FLOAT4, FLOAT8],
    similar_float_types: [],
    byte_types: [],
}

impl_integer! {
    rust: u32,
    natural: INT8,
    smaller_types: [],
    exact_types: [],
    larger_types: [INT8],
    similar_types: [INT2, INT4],
    larger_float_types: [FLOAT8],
    similar_float_types: [FLOAT4],
    byte_types: [],
}

impl_integer! {
    rust: u64,
    natural: INT8,
    smaller_types: [],
    exact_types: [],
    larger_types: [],
    similar_types: [INT2, INT4, INT8],
    larger_float_types: [],
    similar_float_types: [FLOAT4, FLOAT8],
    byte_types: [],
}

// === Floating point types ===

impl FromWireValue<'_> for f32 {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if matches!(oid, oid::INT2 | oid::INT4 | oid::INT8) {
            return parse_integer_as_float_checked!(f32, bytes);
        }
        if !matches!(oid, oid::FLOAT4 | oid::NUMERIC) {
            return Err(Error::Decode(format!("cannot decode oid {} as f32", oid)));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;

        // Handle special text values
        match s {
            "NaN" => return Ok(f32::NAN),
            "Infinity" => return Ok(f32::INFINITY),
            "-Infinity" => return Ok(f32::NEG_INFINITY),
            _ => {}
        }

        let value: f64 = s
            .parse()
            .map_err(|e| Error::Decode(format!("invalid f32: {}", e)))?;

        // Check for overflow
        if value > f32::MAX as f64 || value < f32::MIN as f64 {
            return Err(Error::Decode("NUMERIC value overflows f32".to_string()));
        }

        Ok(value as f32)
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        match oid {
            oid::FLOAT4 => {
                let arr: [u8; 4] = bytes.try_into().map_err(|_unhelpful_err| {
                    Error::Decode(format!("invalid f32 length: {}", bytes.len()))
                })?;
                Ok(f32::from_be_bytes(arr))
            }
            oid::INT2 => Ok(f32::from(read_wire!(INT2, bytes))),
            oid::INT4 => read_integer_as_float_checked!(f32, INT4, bytes),
            oid::INT8 => read_integer_as_float_checked!(f32, INT8, bytes),
            oid::NUMERIC => numeric_to_f32(bytes),
            _ => Err(Error::Decode(format!("cannot decode oid {} as f32", oid))),
        }
    }
}

impl ToWireValue for f32 {
    const NATURAL_OID: Oid = oid::FLOAT4;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::FLOAT4 => {
                buf.extend_from_slice(&4_i32.to_be_bytes());
                buf.extend_from_slice(&self.to_bits().to_be_bytes());
            }
            oid::FLOAT8 => {
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&(*self as f64).to_bits().to_be_bytes());
            }
            oid::NUMERIC => {
                // NUMERIC uses text format
                let s = self.to_string();
                let bytes = s.as_bytes();
                buf.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                buf.extend_from_slice(bytes);
            }
            _ => return Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
        Ok(())
    }
}

impl FromWireValue<'_> for f64 {
    fn from_text(oid: Oid, bytes: &[u8]) -> Result<Self> {
        if matches!(oid, oid::INT2 | oid::INT4 | oid::INT8) {
            return parse_integer_as_float_checked!(f64, bytes);
        }
        if !matches!(oid, oid::FLOAT4 | oid::FLOAT8 | oid::NUMERIC) {
            return Err(Error::Decode(format!("cannot decode oid {} as f64", oid)));
        }
        let s = simdutf8::compat::from_utf8(bytes)
            .map_err(|e| Error::Decode(format!("invalid UTF-8: {}", e)))?;

        // Handle special text values
        match s {
            "NaN" => return Ok(f64::NAN),
            "Infinity" => return Ok(f64::INFINITY),
            "-Infinity" => return Ok(f64::NEG_INFINITY),
            _ => {}
        }

        s.parse()
            .map_err(|e| Error::Decode(format!("invalid f64: {}", e)))
    }

    fn from_binary(oid: Oid, bytes: &[u8]) -> Result<Self> {
        match oid {
            oid::FLOAT4 => {
                let arr: [u8; 4] = bytes.try_into().map_err(|_unhelpful_err| {
                    Error::Decode(format!("invalid f32 length: {}", bytes.len()))
                })?;
                Ok(f32::from_be_bytes(arr) as f64)
            }
            oid::FLOAT8 => {
                let arr: [u8; 8] = bytes.try_into().map_err(|_unhelpful_err| {
                    Error::Decode(format!("invalid f64 length: {}", bytes.len()))
                })?;
                Ok(f64::from_be_bytes(arr))
            }
            oid::INT2 => Ok(f64::from(read_wire!(INT2, bytes))),
            oid::INT4 => Ok(f64::from(read_wire!(INT4, bytes))),
            oid::INT8 => read_integer_as_float_checked!(f64, INT8, bytes),
            oid::NUMERIC => numeric_to_f64(bytes),
            _ => Err(Error::Decode(format!("cannot decode oid {} as f64", oid))),
        }
    }
}

impl ToWireValue for f64 {
    const NATURAL_OID: Oid = oid::FLOAT8;

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match target_oid {
            oid::FLOAT4 => {
                // Note: potential precision loss
                let v = *self as f32;
                if v.is_infinite() && self.is_finite() {
                    return Err(Error::overflow("f64", "FLOAT4"));
                }
                buf.extend_from_slice(&4_i32.to_be_bytes());
                buf.extend_from_slice(&v.to_bits().to_be_bytes());
            }
            oid::FLOAT8 => {
                buf.extend_from_slice(&8_i32.to_be_bytes());
                buf.extend_from_slice(&self.to_bits().to_be_bytes());
            }
            oid::NUMERIC => {
                // NUMERIC uses text format
                let s = self.to_string();
                let bytes = s.as_bytes();
                buf.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                buf.extend_from_slice(bytes);
            }
            _ => return Err(Error::type_mismatch(Self::NATURAL_OID, target_oid)),
        }
        Ok(())
    }
}
