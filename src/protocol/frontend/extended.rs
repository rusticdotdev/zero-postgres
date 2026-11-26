//! Extended query protocol messages.

use crate::conversion::ToParams;
use crate::error::Result;
use crate::protocol::codec::MessageBuilder;
use crate::protocol::types::{FormatCode, Oid, preferred_format};

/// Write a Parse message to create a prepared statement.
///
/// - `name`: Statement name (empty string for unnamed statement)
/// - `query`: SQL query with $1, $2, ... placeholders
/// - `param_oids`: Parameter type OIDs (0 = let server infer)
pub fn write_parse(buf: &mut Vec<u8>, name: &str, query: &str, param_oids: &[Oid]) -> Result<()> {
    super::reject_nul_byte(query, "query")?;
    log::debug!("PARSE {query}");
    let mut msg = MessageBuilder::new(buf, super::msg_type::PARSE);
    msg.write_cstr(name);
    msg.write_cstr(query);
    msg.write_i16(param_oids.len() as i16);
    for &oid in param_oids {
        msg.write_i32(oid as i32);
    }
    msg.finish();
    Ok(())
}

/// Write a Bind message to create a portal from a prepared statement.
///
/// - `portal`: Portal name (empty string for unnamed portal)
/// - `statement_name`: Prepared statement name
/// - `params`: Parameter values (tuple of ToValue types)
/// - `target_oids`: Target OIDs for encoding parameters
///
/// Uses per-parameter format codes based on `preferred_format()`:
/// - NUMERIC uses text format (0)
/// - All other types use binary format (1)
pub fn write_bind<P: ToParams>(
    buf: &mut Vec<u8>,
    portal: &str,
    statement_name: &str,
    params: &P,
    target_oids: &[Oid],
) -> Result<()> {
    super::reject_nul_byte(portal, "portal name")?;
    super::reject_nul_byte(statement_name, "statement name")?;
    log::debug!(
        "BIND {} {}",
        if statement_name.is_empty() {
            "<unnamed statement>"
        } else {
            statement_name
        },
        if portal.is_empty() {
            "<unnamed portal>"
        } else {
            portal
        }
    );
    let mut msg = MessageBuilder::new(buf, super::msg_type::BIND);

    // Portal and statement names
    msg.write_cstr(portal);
    msg.write_cstr(statement_name);

    // Parameter format codes: one per parameter
    let param_count = params.param_count();
    msg.write_i16(param_count as i16);
    for &oid in target_oids {
        msg.write_i16(preferred_format(oid) as i16);
    }

    // Parameter values (count + length-prefixed data)
    msg.write_i16(param_count as i16);
    params.encode(target_oids, msg.buf())?;

    // Result format codes: 1 code that applies to all columns (binary)
    msg.write_i16(1);
    msg.write_i16(FormatCode::Binary as i16);

    msg.finish();
    Ok(())
}

/// Write an Execute message to run a portal.
///
/// - `portal`: Portal name
/// - `max_rows`: Maximum number of rows to return (0 = unlimited)
pub fn write_execute(buf: &mut Vec<u8>, portal: &str, max_rows: u32) -> Result<()> {
    super::reject_nul_byte(portal, "portal name")?;
    log::debug!(
        "EXECUTE {} LIMIT {max_rows}",
        if portal.is_empty() {
            "<unnamed portal>"
        } else {
            portal
        }
    );
    let mut msg = MessageBuilder::new(buf, super::msg_type::EXECUTE);
    msg.write_cstr(portal);
    msg.write_i32(max_rows as i32);
    msg.finish();
    Ok(())
}

/// Write a Describe message to get metadata.
///
/// - `describe_type`: 'S' for statement, 'P' for portal
/// - `name`: Statement or portal name
pub fn write_describe(buf: &mut Vec<u8>, describe_type: u8, name: &str) -> Result<()> {
    super::reject_nul_byte(
        name,
        if describe_type == b'S' {
            "statement name"
        } else {
            "portal name"
        },
    )?;
    log::debug!("DESCRIBE({}) {name}", describe_type as char);
    let mut msg = MessageBuilder::new(buf, super::msg_type::DESCRIBE);
    msg.write_u8(describe_type);
    msg.write_cstr(name);
    msg.finish();
    Ok(())
}

/// Write a Describe message for a statement.
pub fn write_describe_statement(buf: &mut Vec<u8>, name: &str) -> Result<()> {
    write_describe(buf, b'S', name)
}

/// Write a Describe message for a portal.
pub fn write_describe_portal(buf: &mut Vec<u8>, name: &str) -> Result<()> {
    write_describe(buf, b'P', name)
}

/// Write a Close message to release a statement or portal.
///
/// - `close_type`: 'S' for statement, 'P' for portal
/// - `name`: Statement or portal name
pub fn write_close(buf: &mut Vec<u8>, close_type: u8, name: &str) -> Result<()> {
    super::reject_nul_byte(
        name,
        if close_type == b'S' {
            "statement name"
        } else {
            "portal name"
        },
    )?;
    log::debug!("CLOSE({}) {name}", close_type as char);
    let mut msg = MessageBuilder::new(buf, super::msg_type::CLOSE);
    msg.write_u8(close_type);
    msg.write_cstr(name);
    msg.finish();
    Ok(())
}

/// Write a Close message for a statement.
pub fn write_close_statement(buf: &mut Vec<u8>, name: &str) -> Result<()> {
    write_close(buf, b'S', name)
}

/// Write a Close message for a portal.
pub fn write_close_portal(buf: &mut Vec<u8>, name: &str) -> Result<()> {
    write_close(buf, b'P', name)
}

/// Write a Sync message.
///
/// This ends an extended query sequence and causes:
/// - Implicit COMMIT if successful and not in explicit transaction
/// - Implicit ROLLBACK if failed and not in explicit transaction
/// - Server responds with ReadyForQuery
pub fn write_sync(buf: &mut Vec<u8>) {
    log::debug!("SYNC");
    let msg = MessageBuilder::new(buf, super::msg_type::SYNC);
    msg.finish();
}

/// Write a Flush message.
///
/// Forces the server to send all pending responses without waiting for Sync.
/// Useful for pipelining when you need intermediate results.
pub fn write_flush(buf: &mut Vec<u8>) {
    log::debug!("FLUSH");
    let msg = MessageBuilder::new(buf, super::msg_type::FLUSH);
    msg.finish();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn parse() {
        let mut buf = Vec::new();
        write_parse(&mut buf, "stmt1", "SELECT $1::int", &[0]).unwrap();

        assert_eq!(buf[0], b'P');

        // Verify length field
        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        assert_eq!(len as usize, buf.len() - 1);
    }

    #[test]
    fn parse_rejects_nul_byte_in_query() {
        let mut buf = vec![1, 2, 3];
        let err = write_parse(&mut buf, "stmt1", "SELECT 1\0; DROP TABLE t", &[]).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidUsage(message) if message == "NUL byte in query"),
            "{err}"
        );
        assert_eq!(buf, [1, 2, 3]);
    }

    #[test]
    fn writers_reject_nul_byte_in_names() {
        let cases: [(&str, fn(&mut Vec<u8>) -> Result<()>); 7] = [
            ("NUL byte in portal name", |buf| {
                write_bind(buf, "por\0tal", "stmt1", &(), &[])
            }),
            ("NUL byte in statement name", |buf| {
                write_bind(buf, "portal", "st\0mt1", &(), &[])
            }),
            ("NUL byte in portal name", |buf| {
                write_execute(buf, "por\0tal", 0)
            }),
            ("NUL byte in statement name", |buf| {
                write_describe_statement(buf, "st\0mt1")
            }),
            ("NUL byte in portal name", |buf| {
                write_describe_portal(buf, "por\0tal")
            }),
            ("NUL byte in statement name", |buf| {
                write_close_statement(buf, "st\0mt1")
            }),
            ("NUL byte in portal name", |buf| {
                write_close_portal(buf, "por\0tal")
            }),
        ];
        for (index, (expected, write)) in cases.into_iter().enumerate() {
            let mut buf = vec![1, 2, 3];
            let err = write(&mut buf).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidUsage(message) if message == expected),
                "case {index}: {err}"
            );
            assert_eq!(buf, [1, 2, 3], "case {index}");
        }
    }

    #[test]
    fn sync() {
        let mut buf = Vec::new();
        write_sync(&mut buf);

        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], b'S');
        assert_eq!(&buf[1..5], &4_i32.to_be_bytes());
    }

    #[test]
    fn flush() {
        let mut buf = Vec::new();
        write_flush(&mut buf);

        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], b'H');
        assert_eq!(&buf[1..5], &4_i32.to_be_bytes());
    }

    #[test]
    fn execute() {
        let mut buf = Vec::new();
        write_execute(&mut buf, "", 0).unwrap();

        assert_eq!(buf[0], b'E');
        // Length: 4 + 1 (empty string + null) + 4 (max_rows) = 9
        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        assert_eq!(len, 9);
    }
}
