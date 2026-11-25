//! Authentication-related backend messages.

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::error::{Error, Result};
use crate::protocol::codec::{read_cstr, read_i32, read_u32};
use crate::protocol::types::TransactionStatus;

/// Authentication method constants.
pub mod auth_type {
    pub const OK: i32 = 0;
    pub const KERBEROS_V5: i32 = 2;
    pub const CLEARTEXT_PASSWORD: i32 = 3;
    pub const MD5_PASSWORD: i32 = 5;
    pub const GSS: i32 = 7;
    pub const GSS_CONTINUE: i32 = 8;
    pub const SSPI: i32 = 9;
    pub const SASL: i32 = 10;
    pub const SASL_CONTINUE: i32 = 11;
    pub const SASL_FINAL: i32 = 12;
}

/// Authentication message from the server.
#[derive(Debug)]
pub enum AuthenticationMessage<'a> {
    /// Authentication successful
    Ok,
    /// Kerberos V5 authentication required
    KerberosV5,
    /// Cleartext password required
    CleartextPassword,
    /// (Deprecated in pg18) MD5 password required (with 4-byte salt)
    Md5Password { salt: [u8; 4] },
    /// GSS authentication
    Gss,
    /// GSS continue (with additional data)
    GssContinue { data: &'a [u8] },
    /// SSPI authentication
    Sspi,
    /// SASL authentication required (with list of mechanisms)
    Sasl { mechanisms: Vec<&'a str> },
    /// SASL continue (with server-first-message)
    SaslContinue { data: &'a [u8] },
    /// SASL final (with server-final-message)
    SaslFinal { data: &'a [u8] },
}

impl<'a> AuthenticationMessage<'a> {
    /// Parse an Authentication message from payload bytes.
    pub fn parse(payload: &'a [u8]) -> Result<Self> {
        let (auth_type, rest) = read_i32(payload)?;

        match auth_type {
            auth_type::OK => Ok(AuthenticationMessage::Ok),
            auth_type::KERBEROS_V5 => Ok(AuthenticationMessage::KerberosV5),
            auth_type::CLEARTEXT_PASSWORD => Ok(AuthenticationMessage::CleartextPassword),
            auth_type::MD5_PASSWORD => {
                if rest.len() < 4 {
                    return Err(Error::LibraryBug("MD5Password: missing salt".into()));
                }
                let mut salt = [0u8; 4];
                salt.copy_from_slice(&rest[..4]);
                Ok(AuthenticationMessage::Md5Password { salt })
            }
            auth_type::GSS => Ok(AuthenticationMessage::Gss),
            auth_type::GSS_CONTINUE => Ok(AuthenticationMessage::GssContinue { data: rest }),
            auth_type::SSPI => Ok(AuthenticationMessage::Sspi),
            auth_type::SASL => {
                let mut mechanisms = Vec::new();
                let mut data = rest;
                while !data.is_empty() && data[0] != 0 {
                    let (mechanism, remaining) = read_cstr(data)?;
                    mechanisms.push(mechanism);
                    data = remaining;
                }
                Ok(AuthenticationMessage::Sasl { mechanisms })
            }
            auth_type::SASL_CONTINUE => Ok(AuthenticationMessage::SaslContinue { data: rest }),
            auth_type::SASL_FINAL => Ok(AuthenticationMessage::SaslFinal { data: rest }),
            _ => Err(Error::LibraryBug(format!(
                "Unknown authentication type: {}",
                auth_type
            ))),
        }
    }
}

/// BackendKeyData message - contains process ID and secret key for cancellation.
///
/// In protocol 3.2, the secret key is variable-length (4-256 bytes).
#[derive(derive_more::Debug, Clone)]
pub struct BackendKeyData {
    /// Process ID of the backend
    pid: u32,
    /// Secret key for cancellation (variable length in protocol 3.2)
    #[debug("***")]
    secret_key: Vec<u8>,
}

impl BackendKeyData {
    /// Parse a BackendKeyData message from payload bytes.
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 4 {
            return Err(Error::LibraryBug(
                "BackendKeyData: payload too short".into(),
            ));
        }
        let (pid, rest) = read_u32(payload)?;
        if rest.len() < 4 || rest.len() > 256 {
            return Err(Error::LibraryBug(format!(
                "BackendKeyData: invalid secret key length {}",
                rest.len()
            )));
        }
        Ok(Self {
            pid,
            secret_key: rest.to_vec(),
        })
    }

    /// Get the process ID.
    pub fn process_id(&self) -> u32 {
        self.pid
    }

    /// Get the secret key bytes.
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}

/// ParameterStatus message - server parameter name and value.
#[derive(Debug, Clone)]
pub struct ParameterStatus<'a> {
    /// Parameter name
    pub name: &'a str,
    /// Parameter value
    pub value: &'a str,
}

impl<'a> ParameterStatus<'a> {
    /// Parse a ParameterStatus message from payload bytes.
    pub fn parse(payload: &'a [u8]) -> Result<Self> {
        let (name, rest) = read_cstr(payload)?;
        let (value, _) = read_cstr(rest)?;
        Ok(Self { name, value })
    }
}

/// ReadyForQuery message - indicates server is ready for a new query.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct ReadyForQuery {
    /// Transaction status byte
    pub status: u8,
}

impl ReadyForQuery {
    /// Parse a ReadyForQuery message from payload bytes.
    pub fn parse(payload: &[u8]) -> Result<&Self> {
        Self::ref_from_bytes(payload)
            .map_err(|e| Error::LibraryBug(format!("ReadyForQuery: {e:?}")))
    }

    /// Get the transaction status.
    pub fn transaction_status(&self) -> Result<TransactionStatus> {
        TransactionStatus::from_byte(self.status).ok_or_else(|| {
            Error::LibraryBug(format!(
                "ReadyForQuery: invalid transaction status byte {}",
                self.status
            ))
        })
    }
}

/// NotificationResponse message - asynchronous notification from LISTEN/NOTIFY.
#[derive(Debug, Clone)]
pub struct NotificationResponse<'a> {
    /// PID of the notifying backend
    pub pid: u32,
    /// Channel name
    pub channel: &'a str,
    /// Notification payload
    pub payload: &'a str,
}

impl<'a> NotificationResponse<'a> {
    /// Parse a NotificationResponse message from payload bytes.
    pub fn parse(payload: &'a [u8]) -> Result<Self> {
        let (pid, rest) = read_u32(payload)?;
        let (channel, rest) = read_cstr(rest)?;
        let (payload_str, _) = read_cstr(rest)?;
        Ok(Self {
            pid,
            channel,
            payload: payload_str,
        })
    }
}

/// NegotiateProtocolVersion message - server doesn't support requested protocol features.
#[derive(Debug, Clone)]
pub struct NegotiateProtocolVersion<'a> {
    /// Newest protocol version the server supports, as `major << 16 | minor`.
    pub newest_version: i32,
    /// Unrecognized protocol options
    pub unrecognized_options: Vec<&'a str>,
}

impl<'a> NegotiateProtocolVersion<'a> {
    /// Parse a NegotiateProtocolVersion message from payload bytes.
    pub fn parse(payload: &'a [u8], sent_option_count: usize) -> Result<Self> {
        let (newest_version, rest) = read_i32(payload)?;
        let (num_options, mut rest) = read_u32(rest)?;
        if num_options as usize > sent_option_count {
            return Err(Error::LibraryBug(format!(
                "NegotiateProtocolVersion: server rejected {num_options} protocol options but only {sent_option_count} were sent"
            )));
        }

        let mut unrecognized_options = Vec::with_capacity(num_options as usize);
        for _ in 0..num_options {
            let (option, remaining) = read_cstr(rest)?;
            unrecognized_options.push(option);
            rest = remaining;
        }

        Ok(Self {
            newest_version,
            unrecognized_options,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_key_data_debug_hides_secret_key() {
        let mut payload = 31337u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&[222, 173, 190, 239]);
        let key_data = BackendKeyData::parse(&payload).unwrap();

        let debug = format!("{key_data:?}");
        assert!(debug.contains("pid: 31337"), "{debug}");
        assert!(debug.contains("secret_key: ***"), "{debug}");
        assert!(!debug.contains("222, 173, 190, 239"), "{debug}");
        assert!(!debug.contains("222"), "{debug}");
    }

    fn negotiate_payload(newest_version: i32, num_options: u32, options: &[&[u8]]) -> Vec<u8> {
        let mut payload = newest_version.to_be_bytes().to_vec();
        payload.extend_from_slice(&num_options.to_be_bytes());
        for option in options {
            payload.extend_from_slice(option);
            payload.push(0);
        }
        payload
    }

    fn is_option_count_rejection(err: &Error) -> bool {
        matches!(err, Error::LibraryBug(message) if message.starts_with("NegotiateProtocolVersion: server rejected"))
    }

    #[test]
    fn negotiate_parse_accepts_zero_options() {
        for sent_option_count in [0, 1, 5] {
            let payload = negotiate_payload(0x0003_0000, 0, &[]);
            let negotiate = NegotiateProtocolVersion::parse(&payload, sent_option_count).unwrap();
            assert_eq!(negotiate.newest_version, 0x0003_0000);
            assert!(negotiate.unrecognized_options.is_empty());
        }
    }

    #[test]
    fn negotiate_parse_returns_options_in_order() {
        let payload = negotiate_payload(
            0x0003_0002,
            3,
            &[b"_pq_.b", b"_pq_.a", b"_pq_.\xED\x95\x9C"],
        );
        for sent_option_count in [3, 4] {
            let negotiate = NegotiateProtocolVersion::parse(&payload, sent_option_count).unwrap();
            assert_eq!(negotiate.newest_version, 0x0003_0002);
            assert_eq!(
                negotiate.unrecognized_options,
                ["_pq_.b", "_pq_.a", "_pq_.\u{D55C}"]
            );
        }

        let empty_name_payload = negotiate_payload(0x0003_0000, 1, &[b""]);
        let negotiate = NegotiateProtocolVersion::parse(&empty_name_payload, 1).unwrap();
        assert_eq!(negotiate.unrecognized_options, [""]);
    }

    #[test]
    fn negotiate_parse_rejects_more_options_than_sent() {
        for (num_options, sent_option_count) in [(1, 0), (2, 1), (3, 2), (0x8000_0000, 7)] {
            let options: Vec<&[u8]> = vec![b"_pq_.x"; num_options.min(3) as usize];
            let payload = negotiate_payload(0x0003_0000, num_options, &options);
            let err = NegotiateProtocolVersion::parse(&payload, sent_option_count).unwrap_err();
            assert!(
                is_option_count_rejection(&err),
                "{num_options} {sent_option_count}: {err}"
            );
            assert!(err.to_string().contains(&num_options.to_string()), "{err}");
        }
    }

    #[test]
    fn negotiate_parse_rejects_u32_max_option_count_before_allocating() {
        for sent_option_count in [0, 1, u16::MAX as usize] {
            let payload = negotiate_payload(0x0003_0000, u32::MAX, &[]);
            let err = NegotiateProtocolVersion::parse(&payload, sent_option_count).unwrap_err();
            assert!(is_option_count_rejection(&err), "{err}");
            assert!(err.to_string().contains("4294967295"), "{err}");
        }
    }

    #[test]
    fn negotiate_parse_rejects_malformed_payload_within_bound() {
        let mut no_terminator = negotiate_payload(0x0003_0000, 1, &[]);
        no_terminator.extend_from_slice(b"_pq_.x");
        let cases: [(Vec<u8>, usize); 6] = [
            (negotiate_payload(0x0003_0000, 2, &[b"_pq_.x"]), 2),
            (negotiate_payload(0x0003_0000, 1, &[]), 1),
            (negotiate_payload(0x0003_0000, 3, &[]), 3),
            (no_terminator, 1),
            (negotiate_payload(0x0003_0000, 1, &[b"_pq_.\xFF"]), 1),
            (0x0003_0000i32.to_be_bytes().to_vec(), 0),
        ];
        for (payload, sent_option_count) in cases {
            let err = NegotiateProtocolVersion::parse(&payload, sent_option_count).unwrap_err();
            assert!(matches!(err, Error::LibraryBug(_)), "{payload:?}: {err}");
            assert!(!is_option_count_rejection(&err), "{payload:?}: {err}");
        }
    }

    #[test]
    fn ready_for_query_maps_valid_status_bytes() {
        for (payload, expected) in [
            (b"I", TransactionStatus::Idle),
            (b"T", TransactionStatus::InTransaction),
            (b"E", TransactionStatus::Failed),
        ] {
            let ready = ReadyForQuery::parse(payload).unwrap();
            assert_eq!(ready.transaction_status().unwrap(), expected);
        }
    }

    #[test]
    fn ready_for_query_rejects_invalid_status_bytes() {
        for payload in [b"\0", b"i", b"t", b"e", b"X", b"\x7F", b"\xFF"] {
            let ready = ReadyForQuery::parse(payload).unwrap();
            let err = ready.transaction_status().unwrap_err();
            assert!(
                matches!(&err, Error::LibraryBug(message) if message.starts_with("ReadyForQuery: invalid transaction status byte")),
                "{payload:?}: {err}"
            );
        }
    }
}
