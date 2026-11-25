#![cfg(all(feature = "tokio", feature = "compio"))]
#![allow(clippy::panic_in_result_fn)]

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zero_postgres::{ClientTimeout, Error, Opts};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TIMEOUT: Duration = Duration::from_millis(300);
const TIMEOUT_TOLERANCE: Duration = Duration::from_millis(20);
const UPPER_BOUND: Duration = Duration::from_secs(5);
const SSL_REQUEST_CODE: u32 = 80_877_103;

// ─── Fake Server ──────────────────────────────────────────────────────────────

struct FakeServer {
    port: u16,
    handle: JoinHandle<std::io::Result<()>>,
}

impl FakeServer {
    fn spawn<F>(behavior: F) -> std::io::Result<Self>
    where
        F: FnOnce(TcpStream) -> std::io::Result<()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept()?;
            behavior(stream)
        });
        Ok(Self { port, handle })
    }

    fn silent() -> std::io::Result<Self> {
        Self::spawn(drain)
    }

    fn unresponsive_after_startup() -> std::io::Result<Self> {
        Self::spawn(|mut stream| {
            read_startup(&mut stream)?;
            write_ready(&mut stream)?;
            drain(stream)
        })
    }

    fn slow_responder(delay: Duration) -> std::io::Result<Self> {
        Self::spawn(move |mut stream| {
            read_startup(&mut stream)?;
            write_ready(&mut stream)?;
            loop {
                let mut header = [0u8; 5];
                match stream.read_exact(&mut header) {
                    Ok(()) => {}
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(()),
                    Err(error) => return Err(error),
                }
                let [tag, length @ ..] = header;
                let mut body = vec![0u8; (u32::from_be_bytes(length) as usize).saturating_sub(4)];
                stream.read_exact(&mut body)?;
                match tag {
                    b'Q' => {
                        thread::sleep(delay);
                        write_command_complete(&mut stream, "SELECT 1")?;
                        write_ready_for_query(&mut stream)?;
                    }
                    b'X' => return drain(stream),
                    _ => {}
                }
            }
        })
    }

    fn opts(&self) -> Opts {
        Opts {
            host: "127.0.0.1".into(),
            port: self.port,
            user: "u".into(),
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

fn drain(mut stream: TcpStream) -> std::io::Result<()> {
    std::io::copy(&mut stream, &mut std::io::sink())?;
    Ok(())
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

fn write_ready(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0])?;
    write_ready_for_query(stream)
}

fn write_ready_for_query(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(&[b'Z', 0, 0, 0, 5, b'I'])
}

fn write_command_complete(stream: &mut TcpStream, tag: &str) -> std::io::Result<()> {
    let length = u32::try_from(4 + tag.len() + 1)
        .map_err(|_overflow| std::io::Error::from(ErrorKind::InvalidInput))?;
    let mut message = vec![b'C'];
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(tag.as_bytes());
    message.push(0);
    stream.write_all(&message)
}

// ─── Assertions ───────────────────────────────────────────────────────────────

fn assert_timed_out<T>(result: Result<T, Error>, elapsed: Duration, timeout: Duration) {
    let error = result.err();
    assert!(
        matches!(&error, Some(Error::Io(io_error)) if io_error.kind() == ErrorKind::TimedOut),
        "expected Error::Io(TimedOut), got {error:?}"
    );
    assert!(
        elapsed >= timeout.saturating_sub(TIMEOUT_TOLERANCE),
        "timed out too early: {elapsed:?} < {timeout:?}"
    );
    assert!(
        elapsed < UPPER_BOUND,
        "timed out too late: {elapsed:?} >= {UPPER_BOUND:?}"
    );
}

// ─── Connect Timeout ──────────────────────────────────────────────────────────

#[tokio::test]
async fn tokio_connect_timeout_against_silent_server() -> TestResult {
    let server = FakeServer::silent()?;
    let mut opts = server.opts();
    opts.client_timeout.connect = Some(TIMEOUT);
    let started = Instant::now();
    let result = zero_postgres::tokio::Conn::new(opts).await;
    assert_timed_out(result, started.elapsed(), TIMEOUT);
    server.join()
}

#[compio::test]
async fn compio_connect_timeout_against_silent_server() -> TestResult {
    let server = FakeServer::silent()?;
    let mut opts = server.opts();
    opts.client_timeout.connect = Some(TIMEOUT);
    let started = Instant::now();
    let result = zero_postgres::compio::Conn::new(opts).await;
    assert_timed_out(result, started.elapsed(), TIMEOUT);
    server.join_on_compio().await
}

// ─── Query Timeout ────────────────────────────────────────────────────────────

const SHORT_CONNECT_TIMEOUT: Duration = Duration::from_millis(100);
const PAST_CONNECT_DEADLINE: Duration = Duration::from_millis(250);

#[tokio::test]
async fn tokio_query_timeout_breaks_connection() -> TestResult {
    let server = FakeServer::unresponsive_after_startup()?;
    let mut opts = server.opts();
    opts.client_timeout.connect = Some(SHORT_CONNECT_TIMEOUT);
    opts.client_timeout.query = Some(TIMEOUT);
    let mut conn = zero_postgres::tokio::Conn::new(opts).await?;
    assert!(!conn.is_broken());
    tokio::time::sleep(PAST_CONNECT_DEADLINE).await;

    let started = Instant::now();
    let result = conn.query_drop("SELECT 1").await;
    assert_timed_out(result, started.elapsed(), TIMEOUT);
    assert!(conn.is_broken());

    let retried = Instant::now();
    let second = conn.query_drop("SELECT 2").await;
    assert!(second.is_err(), "query on broken connection succeeded");
    assert!(retried.elapsed() < UPPER_BOUND);
    assert!(conn.is_broken());

    drop(conn);
    server.join()
}

#[compio::test]
async fn compio_query_timeout_breaks_connection() -> TestResult {
    let server = FakeServer::unresponsive_after_startup()?;
    let mut opts = server.opts();
    opts.client_timeout.connect = Some(SHORT_CONNECT_TIMEOUT);
    opts.client_timeout.query = Some(TIMEOUT);
    let mut conn = zero_postgres::compio::Conn::new(opts).await?;
    assert!(!conn.is_broken());
    compio::time::sleep(PAST_CONNECT_DEADLINE).await;

    let started = Instant::now();
    let result = conn.query_drop("SELECT 1").await;
    assert_timed_out(result, started.elapsed(), TIMEOUT);
    assert!(conn.is_broken());

    let retried = Instant::now();
    let second = conn.query_drop("SELECT 2").await;
    assert!(second.is_err(), "query on broken connection succeeded");
    assert!(retried.elapsed() < UPPER_BOUND);
    assert!(conn.is_broken());

    drop(conn);
    server.join_on_compio().await
}

const RESPONSE_DELAY: Duration = Duration::from_millis(150);
const QUERY_COUNT: u32 = 4;

#[tokio::test]
async fn tokio_query_timeout_is_per_request() -> TestResult {
    let server = FakeServer::slow_responder(RESPONSE_DELAY)?;
    let mut opts = server.opts();
    opts.client_timeout.query = Some(TIMEOUT);
    let mut conn = zero_postgres::tokio::Conn::new(opts).await?;
    let started = Instant::now();
    for _ in 0..QUERY_COUNT {
        conn.query_drop("SELECT 1").await?;
    }
    assert!(started.elapsed() > TIMEOUT);
    assert!(!conn.is_broken());
    drop(conn);
    server.join()
}

#[compio::test]
async fn compio_query_timeout_is_per_request() -> TestResult {
    let server = FakeServer::slow_responder(RESPONSE_DELAY)?;
    let mut opts = server.opts();
    opts.client_timeout.query = Some(TIMEOUT);
    let mut conn = zero_postgres::compio::Conn::new(opts).await?;
    let started = Instant::now();
    for _ in 0..QUERY_COUNT {
        conn.query_drop("SELECT 1").await?;
    }
    assert!(started.elapsed() > TIMEOUT);
    assert!(!conn.is_broken());
    drop(conn);
    server.join_on_compio().await
}

// ─── URL Parsing ──────────────────────────────────────────────────────────────

const TIMEOUT_KEYS: [&str; 5] = [
    "client_timeout.connect",
    "client_timeout.query",
    "client_timeout.tcp_keepalive_idle_secs",
    "client_timeout.tcp_keepalive_interval_secs",
    "client_timeout.tcp_keepalive_count",
];

#[test]
fn url_parses_timeout_options() -> TestResult {
    let opts = Opts::try_from(
        "postgres://u@localhost/db?client_timeout.connect=2.5&client_timeout.query=0&client_timeout.tcp_keepalive_idle_secs=30&client_timeout.tcp_keepalive_interval_secs=5&client_timeout.tcp_keepalive_count=3",
    )?;
    assert_eq!(
        opts.client_timeout.connect,
        Some(Duration::from_millis(2500))
    );
    assert_eq!(opts.client_timeout.query, None);
    assert_eq!(opts.client_timeout.tcp_keepalive_idle_secs, 30);
    assert_eq!(opts.client_timeout.tcp_keepalive_interval_secs, 5);
    assert_eq!(opts.client_timeout.tcp_keepalive_count, 3);
    assert!(
        opts.params
            .iter()
            .all(|(name, _)| !TIMEOUT_KEYS.contains(&name.as_str())),
        "{:?}",
        opts.params
    );
    Ok(())
}

fn assert_default_timeouts(opts: &Opts) {
    assert_eq!(opts.client_timeout.connect, Some(Duration::from_secs(5)));
    assert_eq!(opts.client_timeout.query, Some(Duration::from_secs(5)));
    assert_eq!(opts.client_timeout.tcp_keepalive_idle_secs, 1);
    assert_eq!(opts.client_timeout.tcp_keepalive_interval_secs, 1);
    assert_eq!(opts.client_timeout.tcp_keepalive_count, 5);
}

#[test]
fn default_timeout_options() -> TestResult {
    assert_default_timeouts(&Opts::default());
    let client_timeout = ClientTimeout::default();
    assert_eq!(client_timeout.connect, Some(Duration::from_secs(5)));
    assert_eq!(client_timeout.query, Some(Duration::from_secs(5)));
    assert_eq!(client_timeout.tcp_keepalive_idle_secs, 1);
    assert_eq!(client_timeout.tcp_keepalive_interval_secs, 1);
    assert_eq!(client_timeout.tcp_keepalive_count, 5);
    assert_default_timeouts(&Opts::try_from("postgres://u@localhost/db")?);
    Ok(())
}

#[test]
fn url_last_timeout_option_wins() -> TestResult {
    let opts = Opts::try_from(
        "postgres://u@localhost/db?client_timeout.connect=1&client_timeout.connect=0&client_timeout.query=0&client_timeout.query=0.25",
    )?;
    assert_eq!(opts.client_timeout.connect, None);
    assert_eq!(opts.client_timeout.query, Some(Duration::from_millis(250)));
    assert!(opts.params.is_empty(), "{:?}", opts.params);
    Ok(())
}

#[test]
fn url_rejects_invalid_timeout_options() {
    for query in [
        "client_timeout.connect=abc",
        "client_timeout.connect=",
        "client_timeout.connect=-1",
        "client_timeout.query=NaN",
        "client_timeout.query=inf",
        "client_timeout.tcp_keepalive_idle_secs=0",
        "client_timeout.tcp_keepalive_interval_secs=0",
        "client_timeout.tcp_keepalive_idle_secs=1.5",
        "client_timeout.tcp_keepalive_interval_secs=1.5",
        "client_timeout.tcp_keepalive_count=0",
        "client_timeout.tcp_keepalive_count=-1",
        "client_timeout.tcp_keepalive_count=4294967296",
        "client_timeout.tcp_keepalive_count=1.5",
    ] {
        let result = Opts::try_from(format!("postgres://u@localhost/db?{query}").as_str());
        assert!(
            matches!(result, Err(Error::InvalidUsage(_))),
            "{query} gave {:?}",
            result.map(|opts| opts.params)
        );
    }
}

#[test]
fn url_statement_timeout_stays_in_params() -> TestResult {
    let opts = Opts::try_from("postgres://u@localhost/db?statement_timeout=5s")?;
    assert_eq!(
        opts.params,
        [("statement_timeout".to_string(), "5s".to_string())]
    );
    assert_default_timeouts(&opts);
    Ok(())
}
