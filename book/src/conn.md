# Connection

A connection can be made with a URL string or `Opts`.

An URL can start with
- `pg://`
- `postgres://`
- `postgresql://`

The URL `pg://{USER}:{PASSWORD}@{HOST}:{PORT}/{DATABASE}?PARAM1=VALUE1&PARAM2=VALUE2` is equivalent to:

```rust,ignore
let mut opts = Opts::default();
opts.host = HOST;
opts.port = PORT;
opts.user = USER;
opts.password = Some(PASSWORD);
opts.database = Some(DATABASE);
opts.params.push((PARAM1, VALUE1));
opts.params.push((PARAM2, VALUE2));
```

See [`Opts`](https://docs.rs/zero-postgres/latest/zero_postgres/struct.Opts.html) for all available options.

## Sync

```rust,ignore
use zero_postgres::sync::Conn;

let mut conn = Conn::new("postgres://test:1234@localhost/test_db")?;
```

## Async

```rust,ignore
use zero_postgres::tokio::Conn;

let mut conn = Conn::new("postgres://test:1234@localhost/test_db").await?;
```

## Unix Socket

```rust,ignore
use zero_postgres::sync::Conn;
use zero_postgres::Opts;

let mut opts = Opts::default();
opts.socket = Some("/var/run/postgresql/.s.PGSQL.5432".to_string());
opts.database = Some("test".to_string());
let mut conn = Conn::new(opts)?;
```

## Upgrade to Unix Socket

By default, `upgrade_to_unix_socket` is `true`.

If `upgrade_to_unix_socket` is `true` and the TCP peer IP is local, the driver queries `SHOW unix_socket_directories` to get the Unix socket path, then reconnects using the socket for better performance.

For production, disable this flag and use explicit TCP or Unix socket:

```rust,ignore
let mut opts: Opts = "postgres://test:1234@localhost".try_into()?;
opts.upgrade_to_unix_socket = false;
let mut conn = Conn::new(opts)?;
```

## Authentication Methods

- Supported: `trust`, `reject`, `scram-sha-256`, `md5`, `password`, `ident`, `peer`, `ldap`, `radius`, `pam`, `bsd`, `cert`, `oauth`
- Todo: `scram-sha-256` with channel binding, `gss`, `sspi`

### OAuth

Set `Opts.oauth_bearer_token_fn` to send a bearer token when the server asks for `OAUTHBEARER`.
The token is sent like a cleartext password, so use `TlsMode::Require`.

When the server rejects the token, it sends a JSON document such as `{"status":"invalid_token","openid-configuration":"...","scope":"..."}` and then fails the connection.
Set `Opts.oauth_discovery_fn` to receive that JSON.

If only `oauth_discovery_fn` is set, the driver sends an empty `auth` value. The server answers with the same JSON, which tells you where to get a token, and the connection fails.

```rust,ignore
opts.oauth_bearer_token_fn = Some(Arc::new(|| Ok(current_token().into())));
opts.oauth_discovery_fn = Some(Arc::new(|error_json| log::warn!("{error_json}")));
```
