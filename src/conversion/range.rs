#[cfg(test)]
#[path = "range_tests.rs"]
mod tests;

use core::ops::{Bound, Range, RangeFrom, RangeInclusive, RangeTo, RangeToInclusive};

use crate::error::{Error, Result};
use crate::protocol::types::{Oid, oid};

use super::{FromWireValue, ToWireValue};

const FLAG_EMPTY: u8 = 0x01;
const FLAG_LOWER_INCLUDED: u8 = 0x02;
const FLAG_UPPER_INCLUDED: u8 = 0x04;
const FLAG_LOWER_UNBOUNDED: u8 = 0x08;
const FLAG_UPPER_UNBOUNDED: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PgRange<T> {
    Empty,
    NonEmpty { lower: Bound<T>, upper: Bound<T> },
}

#[expect(clippy::panic)]
const fn range_oid_for_element(element_oid: Oid) -> Oid {
    match element_oid {
        oid::INT2 | oid::INT4 => oid::INT4RANGE,
        oid::INT8 => oid::INT8RANGE,
        oid::DATE => oid::DATERANGE,
        oid::TIMESTAMP => oid::TSRANGE,
        oid::TIMESTAMPTZ => oid::TSTZRANGE,
        _ => panic!("no supported PostgreSQL range type for this element type"),
    }
}

const fn element_oid_of_range(range_oid: Oid) -> Option<Oid> {
    match range_oid {
        oid::INT4RANGE => Some(oid::INT4),
        oid::INT8RANGE => Some(oid::INT8),
        oid::DATERANGE => Some(oid::DATE),
        oid::TSRANGE => Some(oid::TIMESTAMP),
        oid::TSTZRANGE => Some(oid::TIMESTAMPTZ),
        _ => None,
    }
}

// ─── Encoding ────────────────────────────────────────────────────────────────

fn fill_length_prefix(buf: &mut [u8], length_position: usize) {
    let length = buf.len() - length_position - 4;
    if let Some(length_bytes) = buf.get_mut(length_position..length_position + 4) {
        length_bytes.copy_from_slice(&(length as i32).to_be_bytes());
    }
}

fn encode_bound_value<T: ToWireValue>(
    bound: Bound<&T>,
    element_oid: Oid,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let (Bound::Included(value) | Bound::Excluded(value)) = bound else {
        return Ok(());
    };
    let value_position = buf.len();
    value.encode(element_oid, buf)?;
    if buf
        .get(value_position..)
        .is_some_and(|encoded| encoded.starts_with(&(-1_i32).to_be_bytes()))
    {
        return Err(Error::Encode("range bound cannot be NULL".into()));
    }
    Ok(())
}

fn is_integer_max(range_oid: Oid, encoded_bound: &[u8]) -> bool {
    match range_oid {
        oid::INT4RANGE => {
            encoded_bound.strip_prefix(&4_i32.to_be_bytes()) == Some(&i32::MAX.to_be_bytes())
        }
        oid::INT8RANGE => {
            encoded_bound.strip_prefix(&8_i32.to_be_bytes()) == Some(&i64::MAX.to_be_bytes())
        }
        _ => false,
    }
}

fn encode_flags_and_bounds<T: ToWireValue + PartialOrd>(
    lower: Bound<&T>,
    upper: Bound<&T>,
    target_oid: Oid,
    element_oid: Oid,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let lower_flag = match lower {
        Bound::Included(_) => FLAG_LOWER_INCLUDED,
        Bound::Excluded(_) => 0,
        Bound::Unbounded => FLAG_LOWER_UNBOUNDED,
    };
    let upper_flag = match upper {
        Bound::Included(_) => FLAG_UPPER_INCLUDED,
        Bound::Excluded(_) => 0,
        Bound::Unbounded => FLAG_UPPER_UNBOUNDED,
    };
    let mut server_treats_as_empty = false;
    if let (
        Bound::Included(lower_value) | Bound::Excluded(lower_value),
        Bound::Included(upper_value) | Bound::Excluded(upper_value),
    ) = (lower, upper)
    {
        if lower_value > upper_value {
            return Err(Error::Encode(
                "range lower bound must be less than or equal to range upper bound".into(),
            ));
        }
        let both_included = lower_flag == FLAG_LOWER_INCLUDED && upper_flag == FLAG_UPPER_INCLUDED;
        server_treats_as_empty = lower_value == upper_value && !both_included;
    }

    buf.push(lower_flag | upper_flag);
    let lower_position = buf.len();
    encode_bound_value(lower, element_oid, buf)?;
    let upper_position = buf.len();
    encode_bound_value(upper, element_oid, buf)?;

    let (encoded_lower, encoded_upper) = buf
        .get(lower_position..)
        .unwrap_or_default()
        .split_at(upper_position - lower_position);
    let server_increments_lower = matches!(lower, Bound::Excluded(_));
    let server_increments_upper = matches!(upper, Bound::Included(_));
    if !server_treats_as_empty
        && ((server_increments_lower && is_integer_max(target_oid, encoded_lower))
            || (server_increments_upper && is_integer_max(target_oid, encoded_upper)))
    {
        return Err(Error::Encode(
            "range bound is the largest integer, so the server cannot store the range".into(),
        ));
    }
    Ok(())
}

fn encode_range_parameter<T: ToWireValue + PartialOrd>(
    lower: Bound<&T>,
    upper: Bound<&T>,
    natural_oid: Oid,
    target_oid: Oid,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let Some(element_oid) = element_oid_of_range(target_oid) else {
        return Err(Error::type_mismatch(natural_oid, target_oid));
    };
    let length_position = buf.len();
    buf.extend_from_slice(&0_i32.to_be_bytes());
    if let Err(error) = encode_flags_and_bounds(lower, upper, target_oid, element_oid, buf) {
        buf.truncate(length_position);
        return Err(error);
    }
    fill_length_prefix(buf, length_position);
    Ok(())
}

fn encode_empty_range_parameter(
    natural_oid: Oid,
    target_oid: Oid,
    buf: &mut Vec<u8>,
) -> Result<()> {
    if element_oid_of_range(target_oid).is_none() {
        return Err(Error::type_mismatch(natural_oid, target_oid));
    }
    buf.extend_from_slice(&1_i32.to_be_bytes());
    buf.push(FLAG_EMPTY);
    Ok(())
}

macro_rules! impl_range_encode {
    ($range:ident, |$value:ident| $lower:expr, $upper:expr) => {
        impl<T: ToWireValue + PartialOrd> ToWireValue for $range<T> {
            const NATURAL_OID: Oid = range_oid_for_element(T::NATURAL_OID);

            fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
                let $value = self;
                encode_range_parameter($lower, $upper, Self::NATURAL_OID, target_oid, buf)
            }
        }
    };
}

impl_range_encode!(
    Range,
    |range| Bound::Included(&range.start),
    Bound::Excluded(&range.end)
);
impl_range_encode!(
    RangeFrom,
    |range| Bound::Included(&range.start),
    Bound::Unbounded
);
impl_range_encode!(
    RangeTo,
    |range| Bound::Unbounded,
    Bound::Excluded(&range.end)
);
impl_range_encode!(
    RangeToInclusive,
    |range| Bound::Unbounded,
    Bound::Included(&range.end)
);

impl<T: ToWireValue + PartialOrd> ToWireValue for RangeInclusive<T> {
    const NATURAL_OID: Oid = range_oid_for_element(T::NATURAL_OID);

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        let exhausted_by_iteration = self.is_empty() && self.start() == self.end();
        if exhausted_by_iteration {
            return encode_empty_range_parameter(Self::NATURAL_OID, target_oid, buf);
        }
        encode_range_parameter(
            Bound::Included(self.start()),
            Bound::Included(self.end()),
            Self::NATURAL_OID,
            target_oid,
            buf,
        )
    }
}

impl<T: ToWireValue + PartialOrd> ToWireValue for PgRange<T> {
    const NATURAL_OID: Oid = range_oid_for_element(T::NATURAL_OID);

    fn encode(&self, target_oid: Oid, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            PgRange::Empty => encode_empty_range_parameter(Self::NATURAL_OID, target_oid, buf),
            PgRange::NonEmpty { lower, upper } => encode_range_parameter(
                lower.as_ref(),
                upper.as_ref(),
                Self::NATURAL_OID,
                target_oid,
                buf,
            ),
        }
    }
}

// ─── Decoding ────────────────────────────────────────────────────────────────

fn take_bound_from_binary<'a, T: FromWireValue<'a>>(
    unbounded: bool,
    included: bool,
    element_oid: Oid,
    unread: &mut &'a [u8],
) -> Result<Bound<T>> {
    if unbounded {
        return Ok(Bound::Unbounded);
    }
    let (length, rest) = unread
        .split_first_chunk::<4>()
        .ok_or_else(|| Error::Decode("range bound length is truncated".into()))?;
    let length = usize::try_from(i32::from_be_bytes(*length))
        .map_err(|_unhelpful_err| Error::Decode("range bound cannot be NULL".into()))?;
    let (value, rest) = rest
        .split_at_checked(length)
        .ok_or_else(|| Error::Decode("range bound value is truncated".into()))?;
    *unread = rest;
    let value = T::from_binary(element_oid, value)?;
    Ok(if included {
        Bound::Included(value)
    } else {
        Bound::Excluded(value)
    })
}

fn range_from_binary<'a, T: FromWireValue<'a>>(oid: Oid, bytes: &'a [u8]) -> Result<PgRange<T>> {
    let element_oid = element_oid_of_range(oid)
        .ok_or_else(|| Error::Decode(format!("cannot decode oid {} as range", oid)))?;
    let Some((&flags, mut unread)) = bytes.split_first() else {
        return Err(Error::Decode("range flags are missing".into()));
    };
    let range = if flags & FLAG_EMPTY != 0 {
        PgRange::Empty
    } else {
        PgRange::NonEmpty {
            lower: take_bound_from_binary(
                flags & FLAG_LOWER_UNBOUNDED != 0,
                flags & FLAG_LOWER_INCLUDED != 0,
                element_oid,
                &mut unread,
            )?,
            upper: take_bound_from_binary(
                flags & FLAG_UPPER_UNBOUNDED != 0,
                flags & FLAG_UPPER_INCLUDED != 0,
                element_oid,
                &mut unread,
            )?,
        }
    };
    if !unread.is_empty() {
        return Err(Error::Decode(format!(
            "range has {} trailing bytes",
            unread.len()
        )));
    }
    Ok(range)
}

fn take_bound_from_text<'a, T: FromWireValue<'a>>(
    included: bool,
    element_oid: Oid,
    unread: &mut &'a [u8],
) -> Result<Bound<T>> {
    let value = if let Some(quoted) = unread.strip_prefix(b"\"") {
        let (value, rest) = memchr::memchr(b'"', quoted)
            .and_then(|closing_quote| quoted.split_at_checked(closing_quote))
            .ok_or_else(|| Error::Decode("range bound has no closing quote".into()))?;
        let rest = rest.get(1..).unwrap_or_default();
        if memchr::memchr(b'\\', value).is_some() || rest.starts_with(b"\"") {
            return Err(Error::Decode(
                "range bound with an escaped character is not supported".into(),
            ));
        }
        *unread = rest;
        value
    } else {
        let (value, rest) = unread.split_at(memchr::memchr(b',', unread).unwrap_or(unread.len()));
        *unread = rest;
        if value.is_empty() {
            return Ok(Bound::Unbounded);
        }
        value
    };
    let value = T::from_text(element_oid, value)?;
    Ok(if included {
        Bound::Included(value)
    } else {
        Bound::Excluded(value)
    })
}

fn range_from_text<'a, T: FromWireValue<'a>>(oid: Oid, text: &'a [u8]) -> Result<PgRange<T>> {
    let element_oid = element_oid_of_range(oid)
        .ok_or_else(|| Error::Decode(format!("cannot decode oid {} as range", oid)))?;
    if text == b"empty" {
        return Ok(PgRange::Empty);
    }
    let (lower_included, upper_included, between_brackets) = match text {
        [b'[', between_brackets @ .., b']'] => (true, true, between_brackets),
        [b'[', between_brackets @ .., b')'] => (true, false, between_brackets),
        [b'(', between_brackets @ .., b']'] => (false, true, between_brackets),
        [b'(', between_brackets @ .., b')'] => (false, false, between_brackets),
        _ => return Err(Error::Decode("range has no enclosing brackets".into())),
    };
    let mut unread = between_brackets;
    let lower = take_bound_from_text(lower_included, element_oid, &mut unread)?;
    unread = unread
        .strip_prefix(b",")
        .ok_or_else(|| Error::Decode("range has no comma between bounds".into()))?;
    let upper = take_bound_from_text(upper_included, element_oid, &mut unread)?;
    if !unread.is_empty() {
        return Err(Error::Decode("range has more than two bounds".into()));
    }
    Ok(PgRange::NonEmpty { lower, upper })
}

impl<'a, T: FromWireValue<'a>> FromWireValue<'a> for PgRange<T> {
    fn from_text(oid: Oid, bytes: &'a [u8]) -> Result<Self> {
        range_from_text(oid, bytes)
    }

    fn from_binary(oid: Oid, bytes: &'a [u8]) -> Result<Self> {
        range_from_binary(oid, bytes)
    }
}

macro_rules! impl_range_decode {
    ($range:ident, $lower:pat, $upper:pat => $value:expr) => {
        impl<'a, T: FromWireValue<'a>> FromWireValue<'a> for $range<T> {
            fn from_text(oid: Oid, bytes: &'a [u8]) -> Result<Self> {
                Self::try_from(range_from_text(oid, bytes)?)
            }

            fn from_binary(oid: Oid, bytes: &'a [u8]) -> Result<Self> {
                Self::try_from(range_from_binary(oid, bytes)?)
            }
        }

        impl<T> TryFrom<PgRange<T>> for $range<T> {
            type Error = Error;

            fn try_from(range: PgRange<T>) -> Result<Self> {
                match range {
                    PgRange::NonEmpty {
                        lower: $lower,
                        upper: $upper,
                    } => Ok($value),
                    _ => Err(Error::Decode(format!(
                        "range does not have the bounds of {}",
                        stringify!($range)
                    ))),
                }
            }
        }
    };
}

impl_range_decode!(Range, Bound::Included(start), Bound::Excluded(end) => start..end);
impl_range_decode!(RangeInclusive, Bound::Included(start), Bound::Included(end) => start..=end);
impl_range_decode!(RangeFrom, Bound::Included(start), Bound::Unbounded => start..);
impl_range_decode!(RangeTo, Bound::Unbounded, Bound::Excluded(end) => ..end);
impl_range_decode!(RangeToInclusive, Bound::Unbounded, Bound::Included(end) => ..=end);
