#![cfg(all(
    unix,
    feature = "sync",
    feature = "sync-tls",
    feature = "tokio",
    feature = "tokio-tls",
    feature = "compio",
    feature = "compio-tls"
))]

use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use zero_postgres::rustls::pki_types::CertificateDer;
use zero_postgres::rustls::pki_types::pem::PemObject;
use zero_postgres::rustls::{
    self, CertificateError, ClientConfig, RootCertStore, crypto::aws_lc_rs,
};
use zero_postgres::{Error, Opts, TlsMode};

const SSL_QUERY: &str = "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()";

// ─── Server ───────────────────────────────────────────────────────────────────

struct TlsServer {
    postgres: Child,
    bin_dir: PathBuf,
    directory: PathBuf,
    port: u16,
}

impl TlsServer {
    fn start() -> Self {
        let bin_dir = postgres_bin_dir();
        let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("tls-server-{}", std::process::id()));
        if directory.exists() {
            fs::remove_dir_all(&directory).unwrap();
        }
        fs::create_dir_all(&directory).unwrap();

        generate_certificate_authority(&directory, "trusted_ca", "trusted_ca");
        generate_certificate_authority(&directory, "untrusted_ca", "untrusted_ca");
        generate_certificate_authority(&directory, "wrong_ca", "trusted_ca");
        generate_server_certificate(&directory, "trusted_ca");

        fs::write(directory.join("password"), "1234").unwrap();
        run(Command::new(bin_dir.join("initdb"))
            .arg("--pgdata")
            .arg(directory.join("data"))
            .arg("--pwfile")
            .arg(directory.join("password"))
            .args(["--username=test", "--auth=scram-sha-256", "--no-sync"]));

        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let log = File::create(directory.join("postgres.log")).unwrap();
        let mut postgres = Command::new(bin_dir.join("postgres"))
            .arg("-D")
            .arg(directory.join("data"))
            .args(["-c", &format!("port={port}")])
            .args(["-c", "listen_addresses=localhost"])
            .args(["-c", "unix_socket_directories="])
            .args(["-c", "fsync=off"])
            .args(["-c", "ssl=on"])
            .args(["-c", &setting("ssl_cert_file", &directory, "server.crt")])
            .args(["-c", &setting("ssl_key_file", &directory, "server.key")])
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(30);
        let pid_file = directory.join("data/postmaster.pid");
        while !fs::read_to_string(&pid_file).is_ok_and(|status| status.contains("ready")) {
            assert_eq!(postgres.try_wait().unwrap(), None, "postgres exited early");
            assert!(Instant::now() < deadline, "postgres did not become ready");
            thread::sleep(Duration::from_millis(50));
        }

        Self {
            postgres,
            bin_dir,
            directory,
            port,
        }
    }

    fn opts(&self, tls_mode: TlsMode, certificate_authority: Option<&str>) -> Opts {
        let url = format!("postgres://test:1234@localhost:{}/postgres", self.port);
        let mut opts = Opts::try_from(url.as_str()).unwrap();
        opts.tls_mode = tls_mode;
        opts.tls_config = certificate_authority.map(|name| {
            let mut roots = RootCertStore::empty();
            for certificate in
                CertificateDer::pem_file_iter(self.directory.join(format!("{name}.crt"))).unwrap()
            {
                roots.add(certificate.unwrap()).unwrap();
            }
            Arc::new(
                ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        });
        opts
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        drop(
            Command::new(self.bin_dir.join("pg_ctl"))
                .args(["stop", "--mode=immediate", "--pgdata"])
                .arg(self.directory.join("data"))
                .output(),
        );
        drop(self.postgres.wait());
        drop(fs::remove_dir_all(&self.directory));
    }
}

fn postgres_bin_dir() -> PathBuf {
    let on_path = std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| dir.join("initdb").exists()));
    on_path.unwrap_or_else(|| {
        let output = Command::new("pg_config")
            .arg("--bindir")
            .output()
            .expect("initdb is not on PATH and pg_config is not installed");
        PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
    })
}

fn setting(name: &str, directory: &Path, file_name: &str) -> String {
    format!("{name}={}", directory.join(file_name).display())
}

fn run(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ─── Certificates ─────────────────────────────────────────────────────────────

fn openssl(directory: &Path) -> Command {
    let mut command = Command::new("openssl");
    command.current_dir(directory);
    command
}

fn generate_certificate_authority(directory: &Path, name: &str, common_name: &str) {
    fs::write(
        directory.join("ca.cnf"),
        "[req]\ndistinguished_name = name\n[name]\n[extensions]\n\
         basicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign\n",
    )
    .unwrap();
    run(openssl(directory)
        .args(["req", "-x509", "-nodes", "-days", "2"])
        .args(["-config", "ca.cnf", "-extensions", "extensions"])
        .args(["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"])
        .args(["-subj", &format!("/CN={common_name}")])
        .args(["-keyout", &format!("{name}.key")])
        .args(["-out", &format!("{name}.crt")]));
}

fn generate_server_certificate(directory: &Path, certificate_authority: &str) {
    fs::write(
        directory.join("server.cnf"),
        "basicConstraints = critical, CA:FALSE\nsubjectAltName = DNS:localhost\n",
    )
    .unwrap();
    run(openssl(directory)
        .args(["req", "-new", "-nodes", "-config", "ca.cnf"])
        .args(["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"])
        .args(["-subj", "/CN=localhost"])
        .args(["-keyout", "server.key", "-out", "server.csr"]));
    run(openssl(directory)
        .args(["x509", "-req", "-days", "2", "-CAcreateserial"])
        .args(["-in", "server.csr", "-extfile", "server.cnf"])
        .args(["-CA", &format!("{certificate_authority}.crt")])
        .args(["-CAkey", &format!("{certificate_authority}.key")])
        .args(["-out", "server.crt"]));
}

// ─── Drivers ──────────────────────────────────────────────────────────────────

fn connect_sync(opts: Opts) -> Result<bool, Error> {
    let mut conn = zero_postgres::sync::Conn::new(opts)?;
    let rows: Vec<(bool,)> = conn.query_collect(SSL_QUERY)?;
    Ok(rows[0].0)
}

fn connect_tokio(opts: Opts) -> Result<bool, Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut conn = zero_postgres::tokio::Conn::new(opts).await?;
        let rows: Vec<(bool,)> = conn.query_collect(SSL_QUERY).await?;
        Ok(rows[0].0)
    })
}

fn connect_compio(opts: Opts) -> Result<bool, Error> {
    compio::runtime::Runtime::new()?.block_on(async {
        let mut conn = zero_postgres::compio::Conn::new(opts).await?;
        let rows: Vec<(bool,)> = conn.query_collect(SSL_QUERY).await?;
        Ok(rows[0].0)
    })
}

fn certificate_error(error: &Error) -> Option<&CertificateError> {
    let Error::Io(error) = error else {
        return None;
    };
    match error.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::InvalidCertificate(certificate_error) => Some(certificate_error),
        _ => None,
    }
}

const DRIVERS: [(&str, fn(Opts) -> Result<bool, Error>); 3] = [
    ("sync", connect_sync),
    ("tokio", connect_tokio),
    ("compio", connect_compio),
];

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn tls_modes_against_tls_server() {
    let server = TlsServer::start();
    let mut accepted = vec![(TlsMode::Insecure, None), (TlsMode::ChannelBinding, None)];
    let mut rejected = vec![
        (TlsMode::Pki, None, CertificateError::UnknownIssuer),
        (TlsMode::Hardened, None, CertificateError::UnknownIssuer),
    ];
    for tls_mode in [
        TlsMode::Insecure,
        TlsMode::Pki,
        TlsMode::ChannelBinding,
        TlsMode::Hardened,
    ] {
        accepted.push((tls_mode, Some("trusted_ca")));
        rejected.push((
            tls_mode,
            Some("untrusted_ca"),
            CertificateError::UnknownIssuer,
        ));
        rejected.push((tls_mode, Some("wrong_ca"), CertificateError::BadSignature));
    }
    for (driver, connect) in DRIVERS {
        for &(tls_mode, certificate_authority) in &accepted {
            let is_tls = connect(server.opts(tls_mode, certificate_authority));
            assert!(
                matches!(is_tls, Ok(true)),
                "{driver} {tls_mode:?} {certificate_authority:?}: {is_tls:?}"
            );
        }
        for (tls_mode, certificate_authority, expected) in &rejected {
            let is_tls = connect(server.opts(*tls_mode, *certificate_authority));
            assert!(
                is_tls
                    .as_ref()
                    .is_err_and(|error| certificate_error(error) == Some(expected)),
                "{driver} {tls_mode:?} {certificate_authority:?}: {is_tls:?}"
            );
        }
    }
}
