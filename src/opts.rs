//! Connection options.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use url::Url;

use crate::buffer_pool::{BufferPool, GLOBAL_BUFFER_POOL};
use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMode {
    /// accept any auth method provided by the server
    #[default]
    Insecure,
    /// verifies the server cert and the trust chain
    Pki,
    /// reject all auth methods except SCRAM-PLUS
    ChannelBinding,
    /// pki + channel binding
    Hardened,
}

impl TlsMode {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 4] = [
        Self::Insecure,
        Self::Pki,
        Self::ChannelBinding,
        Self::Hardened,
    ];

    pub(crate) fn requires_tls(self) -> bool {
        self != Self::Insecure
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    pub(crate) fn requires_certificate_verification(self) -> bool {
        matches!(self, Self::Pki | Self::Hardened)
    }

    pub(crate) fn requires_channel_binding(self) -> bool {
        matches!(self, Self::ChannelBinding | Self::Hardened)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTimeout {
    pub connect: Option<Duration>,
    pub query: Option<Duration>,
    pub tcp_keepalive_idle_secs: u32,
    pub tcp_keepalive_interval_secs: u32,
    pub tcp_keepalive_count: u32,
}

impl Default for ClientTimeout {
    fn default() -> Self {
        Self {
            connect: Some(Duration::from_secs(5)),
            query: Some(Duration::from_secs(5)),
            tcp_keepalive_idle_secs: 1,
            tcp_keepalive_interval_secs: 1,
            tcp_keepalive_count: 5,
        }
    }
}

/// Connection options for PostgreSQL.
#[derive(derive_more::Debug, Clone)]
pub struct Opts {
    /// Hostname or IP address.
    ///
    /// Default: `""`
    pub host: String,

    /// Port number for the PostgreSQL server.
    ///
    /// Default: `5432`
    pub port: u16,

    /// Unix socket path.
    ///
    /// Default: `None`
    pub socket: Option<String>,

    /// Username for authentication.
    ///
    /// Default: `""`
    pub user: String,

    /// Database name to use.
    ///
    /// Default: `None`
    pub database: Option<String>,

    /// Password for authentication.
    ///
    /// Default: `None`
    #[debug("{}", if password.is_some() { "Some(***)" } else { "None" })]
    pub password: Option<String>,

    #[debug("{}", if password_fn.is_some() { "Some(..)" } else { "None" })]
    pub password_fn: Option<Arc<dyn Fn() -> Result<String, Error> + Send + Sync>>,

    #[debug("{}", if oauth_bearer_token_fn.is_some() { "Some(..)" } else { "None" })]
    pub oauth_bearer_token_fn:
        Option<Arc<dyn Fn() -> Result<Cow<'static, str>, Error> + Send + Sync>>,

    #[debug("{}", if oauth_discovery_fn.is_some() { "Some(..)" } else { "None" })]
    pub oauth_discovery_fn: Option<Arc<dyn Fn(&str) + Send + Sync>>,

    /// Application name to report to the server.
    ///
    /// Default: `None`
    pub application_name: Option<String>,

    /// Default: `TlsMode::Insecure`
    pub tls_mode: TlsMode,

    /// rustls client config for TLS connections.
    ///
    /// Set this to trust a private CA or to present a client certificate.
    /// Build the config with [`crate::rustls`] so that the rustls versions match,
    /// and with the aws-lc-rs provider, which this crate uses:
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::sync::Arc;
    /// use zero_postgres::rustls::pki_types::{pem::PemObject, CertificateDer};
    /// use zero_postgres::rustls::{crypto::aws_lc_rs, ClientConfig, RootCertStore};
    ///
    /// let mut roots = RootCertStore::empty();
    /// for cert in CertificateDer::pem_file_iter("/etc/myapp/db-ca.pem")? {
    ///     roots.add(cert?)?;
    /// }
    /// let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
    ///     .with_safe_default_protocol_versions()?
    ///     .with_root_certificates(roots)
    ///     .with_no_client_auth();
    ///
    /// let mut opts = zero_postgres::Opts::default();
    /// opts.tls_config = Some(Arc::new(config));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// `None` uses the platform certificate verifier, built once and shared by
    /// all connections.
    ///
    /// Default: `None`
    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    pub tls_config: Option<Arc<rustls::ClientConfig>>,

    /// Additional connection parameters.
    ///
    /// Default: `[]`
    pub params: Vec<(String, String)>,

    /// When connected via TCP to loopback, upgrade to Unix socket for better performance.
    ///
    /// Default: `true`
    pub upgrade_to_unix_socket: bool,

    /// Maximum number of idle connections in the pool.
    ///
    /// Default: `100`
    pub pool_max_idle_conn: usize,

    /// Maximum number of concurrent connections (None = unlimited).
    ///
    /// Default: `None`
    pub pool_max_concurrency: Option<usize>,

    pub client_timeout: ClientTimeout,

    /// Buffer pool for reusing buffers across connections.
    ///
    /// Default: `GLOBAL_BUFFER_POOL`
    pub buffer_pool: Arc<BufferPool>,
}

impl Opts {
    pub(crate) fn get_password(&self) -> Result<Option<Cow<'_, str>>, Error> {
        if let Some(password_fn) = &self.password_fn {
            return password_fn().map(|password| Some(Cow::Owned(password)));
        }
        Ok(self.password.as_deref().map(Cow::Borrowed))
    }

    pub(crate) fn set_tcp_keepalive<S>(&self, socket: &S) -> Result<(), Error>
    where
        for<'a> socket2::SockRef<'a>: From<&'a S>,
    {
        if self.client_timeout.tcp_keepalive_idle_secs == 0
            || self.client_timeout.tcp_keepalive_interval_secs == 0
            || self.client_timeout.tcp_keepalive_count == 0
        {
            return Err(Error::InvalidUsage(format!(
                "tcp_keepalive_idle_secs, tcp_keepalive_interval_secs and tcp_keepalive_count must be at least 1, got {}, {}, {}",
                self.client_timeout.tcp_keepalive_idle_secs,
                self.client_timeout.tcp_keepalive_interval_secs,
                self.client_timeout.tcp_keepalive_count
            )));
        }
        let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(u64::from(
            self.client_timeout.tcp_keepalive_idle_secs,
        )));
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "windows",
        ))]
        let keepalive = keepalive
            .with_interval(Duration::from_secs(u64::from(
                self.client_timeout.tcp_keepalive_interval_secs,
            )))
            .with_retries(self.client_timeout.tcp_keepalive_count);
        socket2::SockRef::from(socket).set_tcp_keepalive(&keepalive)?;
        Ok(())
    }
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 5432,
            socket: None,
            user: String::new(),
            database: None,
            password: None,
            password_fn: None,
            oauth_bearer_token_fn: None,
            oauth_discovery_fn: None,
            application_name: None,
            tls_mode: TlsMode::Insecure,
            #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
            tls_config: None,
            params: Vec::new(),
            upgrade_to_unix_socket: true,
            pool_max_idle_conn: 100,
            pool_max_concurrency: None,
            client_timeout: ClientTimeout::default(),
            buffer_pool: Arc::clone(&GLOBAL_BUFFER_POOL),
        }
    }
}

impl TryFrom<&Url> for Opts {
    type Error = Error;

    /// Parse a PostgreSQL connection URL.
    ///
    /// Format: `(pg|postgres|postgresql)://[user[:password]@]host[:port][/database][?param1=value1&param2=value2&..]`
    ///
    /// The user, password and database are percent-decoded, so characters such as
    /// `/`, `#` and `?` can be written as `%2F`, `%23` and `%3F`. A literal `%`
    /// followed by two hex digits must be written as `%25`.
    ///
    /// Supported query parameters:
    /// - `tls_mode`: insecure, pki, channel-binding, hardened
    /// - `application_name`: application name
    /// - `upgrade_to_unix_socket`: true/True/1/yes/on or false/False/0/no/off
    /// - `pool_max_idle_conn`: maximum idle connections (positive integer)
    /// - `pool_max_concurrency`: maximum concurrent connections (positive integer)
    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        if !["pg", "postgres", "postgresql"].contains(&url.scheme()) {
            return Err(Error::InvalidUsage(format!(
                "Invalid scheme: expected 'pg://', 'postgres://', or 'postgresql://', got '{}://'",
                url.scheme()
            )));
        }

        let mut opts = Opts {
            host: url.host_str().unwrap_or("localhost").to_string(),
            port: url.port().unwrap_or(5432),
            user: percent_decode(url.username())?,
            password: url.password().map(percent_decode).transpose()?,
            database: match url.path().strip_prefix('/') {
                Some(s) if !s.is_empty() => Some(percent_decode(s)?),
                _ => None,
            },
            ..Opts::default()
        };

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "tls_mode" => {
                    opts.tls_mode = match value.to_ascii_lowercase().as_str() {
                        "insecure" => TlsMode::Insecure,
                        "pki" => TlsMode::Pki,
                        "channel-binding" | "channelbinding" => TlsMode::ChannelBinding,
                        "hardened" => TlsMode::Hardened,
                        _ => {
                            return Err(Error::InvalidUsage(format!(
                                "Invalid tls_mode: expected one of ['insecure', 'pki', 'channel-binding', 'hardened'], got {}",
                                value
                            )));
                        }
                    };
                }
                "application_name" => {
                    opts.application_name = Some(value.to_string());
                }
                "upgrade_to_unix_socket" => {
                    opts.upgrade_to_unix_socket = match value.as_ref() {
                        "true" | "True" | "1" | "yes" | "on" => true,
                        "false" | "False" | "0" | "no" | "off" => false,
                        _ => {
                            return Err(Error::InvalidUsage(format!(
                                "Invalid upgrade_to_unix_socket parameter: {}",
                                value
                            )));
                        }
                    };
                }
                "pool_max_idle_conn" => {
                    opts.pool_max_idle_conn = value.parse().map_err(|_unhelpful_err| {
                        Error::InvalidUsage(format!("Invalid pool_max_idle_conn: {}", value))
                    })?;
                }
                "pool_max_concurrency" => {
                    opts.pool_max_concurrency = Some(value.parse().map_err(|_unhelpful_err| {
                        Error::InvalidUsage(format!("Invalid pool_max_concurrency: {}", value))
                    })?);
                }
                "client_timeout.connect" => {
                    opts.client_timeout.connect = parse_seconds(&key, &value)?;
                }
                "client_timeout.query" => {
                    opts.client_timeout.query = parse_seconds(&key, &value)?;
                }
                "client_timeout.tcp_keepalive_idle_secs" => {
                    opts.client_timeout.tcp_keepalive_idle_secs = parse_positive(&key, &value)?;
                }
                "client_timeout.tcp_keepalive_interval_secs" => {
                    opts.client_timeout.tcp_keepalive_interval_secs = parse_positive(&key, &value)?;
                }
                "client_timeout.tcp_keepalive_count" => {
                    opts.client_timeout.tcp_keepalive_count = parse_positive(&key, &value)?;
                }
                _ => {
                    opts.params.push((key.to_string(), value.to_string()));
                }
            }
        }

        Ok(opts)
    }
}

impl TryFrom<&str> for Opts {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let url = Url::parse(s).map_err(|e| Error::InvalidUsage(format!("Invalid URL: {}", e)))?;
        Self::try_from(&url)
    }
}

fn parse_seconds(key: &str, value: &str) -> Result<Option<Duration>, Error> {
    let duration = value
        .parse()
        .ok()
        .and_then(|seconds| Duration::try_from_secs_f64(seconds).ok())
        .ok_or_else(|| Error::InvalidUsage(format!("Invalid {}: {}", key, value)))?;
    Ok((!duration.is_zero()).then_some(duration))
}

fn parse_positive(key: &str, value: &str) -> Result<u32, Error> {
    value
        .parse()
        .ok()
        .filter(|parsed| *parsed > 0)
        .ok_or_else(|| Error::InvalidUsage(format!("Invalid {}: {}", key, value)))
}

fn percent_decode(s: &str) -> Result<String, Error> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|e| Error::InvalidUsage(format!("Invalid UTF-8 in URL: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_encoded_credentials_and_database() {
        let opts = Opts::try_from("postgres://al%40ice:p%40ss%2Fw%3Frd@localhost/my%20db").unwrap();
        assert_eq!(opts.user, "al@ice");
        assert_eq!(opts.password.as_deref(), Some("p@ss/w?rd"));
        assert_eq!(opts.database.as_deref(), Some("my db"));
    }

    #[test]
    fn decodes_raw_at_sign_in_password() {
        let opts = Opts::try_from("postgres://alice:p@ss@localhost/db").unwrap();
        assert_eq!(opts.password.as_deref(), Some("p@ss"));
        assert_eq!(opts.host, "localhost");
    }

    #[test]
    fn keeps_plain_values() {
        let opts = Opts::try_from("postgres://alice:secret@localhost/db").unwrap();
        assert_eq!(opts.user, "alice");
        assert_eq!(opts.password.as_deref(), Some("secret"));
        assert_eq!(opts.database.as_deref(), Some("db"));
    }

    #[test]
    fn rejects_invalid_utf8() {
        Opts::try_from("postgres://alice:%FF@localhost/db").unwrap_err();
    }

    #[test]
    fn password_fn_debug_shows_presence_only() {
        let without_fn = format!("{:?}", Opts::default());
        assert!(without_fn.contains("password_fn: None"), "{without_fn}");

        let opts = Opts {
            password_fn: Some(Arc::new(|| Ok("secret".into()))),
            ..Opts::default()
        };
        let with_fn = format!("{opts:?}");
        assert!(with_fn.contains("password_fn: Some(..)"), "{with_fn}");
        assert!(!with_fn.contains("secret"), "{with_fn}");
    }

    #[test]
    fn password_debug_shows_presence_only() {
        let without_password = format!("{:?}", Opts::default());
        assert!(
            without_password.contains("password: None"),
            "{without_password}"
        );

        let opts = Opts {
            password: Some("secret".into()),
            ..Opts::default()
        };
        let with_password = format!("{opts:?}");
        assert!(
            with_password.contains("password: Some(***)"),
            "{with_password}"
        );
        assert!(!with_password.contains("secret"), "{with_password}");
    }

    #[test]
    fn oauth_bearer_token_fn_debug_shows_presence_only() {
        let without_fn = format!("{:?}", Opts::default());
        assert!(
            without_fn.contains("oauth_bearer_token_fn: None"),
            "{without_fn}"
        );

        let opts = Opts {
            oauth_bearer_token_fn: Some(Arc::new(|| Ok("secret".into()))),
            ..Opts::default()
        };
        let with_fn = format!("{opts:?}");
        assert!(
            with_fn.contains("oauth_bearer_token_fn: Some(..)"),
            "{with_fn}"
        );
        assert!(!with_fn.contains("secret"), "{with_fn}");
    }

    #[test]
    fn oauth_discovery_fn_debug_shows_presence_only() {
        let without_fn = format!("{:?}", Opts::default());
        assert!(
            without_fn.contains("oauth_discovery_fn: None"),
            "{without_fn}"
        );

        let opts = Opts {
            oauth_discovery_fn: Some(Arc::new(|_| {})),
            ..Opts::default()
        };
        let with_fn = format!("{opts:?}");
        assert!(
            with_fn.contains("oauth_discovery_fn: Some(..)"),
            "{with_fn}"
        );
    }

    #[test]
    fn new_auth_options_default_to_none() {
        let opts = Opts::default();
        assert!(opts.password_fn.is_none());
        assert!(opts.oauth_bearer_token_fn.is_none());
        assert!(opts.oauth_discovery_fn.is_none());
    }

    #[test]
    fn tls_mode_defaults_to_insecure() {
        assert_eq!(TlsMode::default(), TlsMode::Insecure);
        assert_eq!(Opts::default().tls_mode, TlsMode::Insecure);
        assert_eq!(
            Opts::try_from("postgres://alice@localhost/db")
                .unwrap()
                .tls_mode,
            TlsMode::Insecure
        );
    }

    #[test]
    fn parses_tls_mode_from_url() {
        for (value, expected) in [
            ("insecure", TlsMode::Insecure),
            ("pki", TlsMode::Pki),
            ("channel-binding", TlsMode::ChannelBinding),
            ("channelbinding", TlsMode::ChannelBinding),
            ("hardened", TlsMode::Hardened),
            ("Insecure", TlsMode::Insecure),
            ("PKI", TlsMode::Pki),
            ("Channel-Binding", TlsMode::ChannelBinding),
            ("ChannelBinding", TlsMode::ChannelBinding),
            ("CHANNELBINDING", TlsMode::ChannelBinding),
            ("HARDENED", TlsMode::Hardened),
        ] {
            let opts =
                Opts::try_from(format!("postgres://alice@localhost/db?tls_mode={value}").as_str())
                    .unwrap();
            assert_eq!(opts.tls_mode, expected, "{value}");
        }
    }

    #[test]
    fn last_tls_mode_parameter_wins() {
        let opts =
            Opts::try_from("postgres://alice@localhost/db?tls_mode=hardened&tls_mode=insecure")
                .unwrap();
        assert_eq!(opts.tls_mode, TlsMode::Insecure);
    }

    #[test]
    fn rejects_invalid_tls_mode() {
        for value in [
            "",
            "secure_pki",
            "secure_channel_binding",
            "channel_binding",
            "channel binding",
            "channel--binding",
            "require",
            "prefer",
            "disable",
            "hardened%20",
            "%00",
        ] {
            let err =
                Opts::try_from(format!("postgres://alice@localhost/db?tls_mode={value}").as_str())
                    .unwrap_err();
            assert!(
                matches!(&err, Error::InvalidUsage(message) if message.contains("Invalid tls_mode")),
                "{value}: {err}"
            );
        }
    }

    #[test]
    fn tls_mode_requires_tls() {
        assert!(!TlsMode::Insecure.requires_tls());
        assert!(TlsMode::Pki.requires_tls());
        assert!(TlsMode::ChannelBinding.requires_tls());
        assert!(TlsMode::Hardened.requires_tls());
    }

    #[cfg(any(feature = "sync-tls", feature = "tokio-tls", feature = "compio-tls"))]
    #[test]
    fn tls_mode_requires_certificate_verification() {
        assert!(!TlsMode::Insecure.requires_certificate_verification());
        assert!(TlsMode::Pki.requires_certificate_verification());
        assert!(!TlsMode::ChannelBinding.requires_certificate_verification());
        assert!(TlsMode::Hardened.requires_certificate_verification());
    }

    #[test]
    fn tls_mode_requires_channel_binding() {
        assert!(!TlsMode::Insecure.requires_channel_binding());
        assert!(!TlsMode::Pki.requires_channel_binding());
        assert!(TlsMode::ChannelBinding.requires_channel_binding());
        assert!(TlsMode::Hardened.requires_channel_binding());
    }
}
