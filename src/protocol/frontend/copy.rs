//! COPY protocol frontend messages.

use crate::error::Result;
use crate::protocol::codec::MessageBuilder;

/// Write a CopyData message.
pub fn write_copy_data(buf: &mut Vec<u8>, data: &[u8]) {
    let mut msg = MessageBuilder::new(buf, super::msg_type::COPY_DATA);
    msg.write_bytes(data);
    msg.finish();
}

/// Write a CopyDone message.
pub fn write_copy_done(buf: &mut Vec<u8>) {
    let msg = MessageBuilder::new(buf, super::msg_type::COPY_DONE);
    msg.finish();
}

/// Write a CopyFail message.
pub fn write_copy_fail(buf: &mut Vec<u8>, error_message: &str) -> Result<()> {
    super::reject_nul_byte(error_message, "CopyFail message")?;
    let mut msg = MessageBuilder::new(buf, super::msg_type::COPY_FAIL);
    msg.write_cstr(error_message);
    msg.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn copy_data() {
        let mut buf = Vec::new();
        write_copy_data(&mut buf, b"hello\tworld\n");

        assert_eq!(buf[0], b'd');
        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        assert_eq!(len as usize, buf.len() - 1);
    }

    #[test]
    fn copy_done() {
        let mut buf = Vec::new();
        write_copy_done(&mut buf);

        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], b'c');
        assert_eq!(&buf[1..5], &4_i32.to_be_bytes());
    }

    #[test]
    fn copy_fail() {
        let mut buf = Vec::new();
        write_copy_fail(&mut buf, "error occurred").unwrap();

        assert_eq!(buf[0], b'f');
    }

    #[test]
    fn copy_fail_rejects_nul_byte() {
        let mut buf = vec![1, 2, 3];
        let err = write_copy_fail(&mut buf, "bad\0message").unwrap_err();
        assert!(
            matches!(&err, Error::InvalidUsage(message) if message == "NUL byte in CopyFail message"),
            "{err}"
        );
        assert_eq!(buf, [1, 2, 3]);
    }
}
