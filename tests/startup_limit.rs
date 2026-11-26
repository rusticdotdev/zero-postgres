#![cfg(all(feature = "sync", feature = "tokio", feature = "compio"))]
#![allow(clippy::panic_in_result_fn)]

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zero_postgres::state::connection::MAX_STARTUP_MESSAGE_LENGTH;
use zero_postgres::{Error, Opts};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const UPPER_BOUND: Duration = Duration::from_secs(5);
const SSL_REQUEST_CODE: u32 = 80_877_103;

// ─── Fake Server ──────────────────────────────────────────────────────────────

struct FakeServer {
    port: u16,
    handle: JoinHandle<std::io::Result<()>>,
}

impl FakeServer {
    fn header_only(length: u32) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept()?;
            read_startup(&mut stream)?;
            let [first, second, third, fourth] = length.to_be_bytes();
            stream.write_all(&[b'R', first, second, third, fourth])?;
            stream.shutdown(Shutdown::Write)?;
            stream.set_read_timeout(Some(UPPER_BOUND))?;
            std::io::copy(&mut stream, &mut std::io::sink())?;
            Ok(())
        });
        Ok(Self { port, handle })
    }

    fn opts(&self) -> Opts {
        Opts {
            host: "127.0.0.1".into(),
            port: self.port,
            user: c"u".into(),
            upgrade_to_unix_socket: false,
            ..Opts::default()
        }
    }

    async fn join_on_compio(self) -> TestResult {
        let started = Instant::now();
        while !self.handle.is_finished() {
            if started.elapsed() >= UPPER_BOUND {
                return Err("fake server did not see the client disconnect".into());
            }
            compio::time::sleep(Duration::from_millis(10)).await;
        }
        self.join()
    }

    fn join(self) -> TestResult {
        self.handle
            .join()
            .map_err(|_panic| "fake server thread panicked")??;
        Ok(())
    }
}

fn read_untyped_packet(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let mut body = vec![0u8; (u32::from_be_bytes(length) as usize).saturating_sub(4)];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn read_startup(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let packet = read_untyped_packet(stream)?;
    if packet.as_slice() == SSL_REQUEST_CODE.to_be_bytes() {
        stream.write_all(b"N")?;
        return read_untyped_packet(stream);
    }
    Ok(packet)
}

fn length_cases() -> Result<[(u32, ErrorKind); 3], Box<dyn std::error::Error>> {
    let limit = u32::try_from(MAX_STARTUP_MESSAGE_LENGTH)?;
    Ok([
        (limit + 1, ErrorKind::InvalidData),
        (u32::MAX, ErrorKind::InvalidData),
        (limit, ErrorKind::UnexpectedEof),
    ])
}

// ─── Assertions ───────────────────────────────────────────────────────────────

fn assert_io_error<T>(result: Result<T, Error>, elapsed: Duration, length: u32, kind: ErrorKind) {
    let error = result.err();
    assert!(
        matches!(&error, Some(Error::Io(io_error)) if io_error.kind() == kind),
        "length {length}: expected Error::Io({kind:?}), got {error:?}"
    );
    if kind == ErrorKind::InvalidData {
        assert_eq!(
            error.map(|error| error.to_string()),
            Some(format!(
                "I/O error: message length {length} exceeds the limit of {MAX_STARTUP_MESSAGE_LENGTH}"
            ))
        );
    }
    assert!(
        elapsed < UPPER_BOUND,
        "length {length}: failed too late: {elapsed:?}"
    );
}

// ─── Startup Message Length ───────────────────────────────────────────────────

#[test]
fn sync_startup_message_length_limit() -> TestResult {
    for (length, kind) in length_cases()? {
        let server = FakeServer::header_only(length)?;
        let started = Instant::now();
        let result = zero_postgres::sync::Conn::new(server.opts());
        assert_io_error(result, started.elapsed(), length, kind);
        server.join()?;
    }
    Ok(())
}

#[tokio::test]
async fn tokio_startup_message_length_limit() -> TestResult {
    for (length, kind) in length_cases()? {
        let server = FakeServer::header_only(length)?;
        let mut opts = server.opts();
        opts.client_timeout.connect = Some(UPPER_BOUND);
        let started = Instant::now();
        let result = zero_postgres::tokio::Conn::new(opts).await;
        assert_io_error(result, started.elapsed(), length, kind);
        server.join()?;
    }
    Ok(())
}

#[compio::test]
async fn compio_startup_message_length_limit() -> TestResult {
    for (length, kind) in length_cases()? {
        let server = FakeServer::header_only(length)?;
        let mut opts = server.opts();
        opts.client_timeout.connect = Some(UPPER_BOUND);
        let started = Instant::now();
        let result = zero_postgres::compio::Conn::new(opts).await;
        assert_io_error(result, started.elapsed(), length, kind);
        server.join_on_compio().await?;
    }
    Ok(())
}
