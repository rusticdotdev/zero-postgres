# zero-postgres

A high-performance PostgreSQL client library for Rust.

[API Reference (docs.rs)](https://docs.rs/zero-postgres) | [User Guide](https://rusticdotdev.github.io/zero-postgres/) | [Wire Protocol](https://htmlpreview.github.io/?https://github.com/rusticdotdev/zero-postgres/blob/main/wire-protocol.html)

Python binding: [pyro-postgres](https://github.com/rusticdotdev/pyro-postgres/).


## Feature Flags

- `derive` (default): `#[derive(FromRow)]` and `#[derive(RefFromRow)]` macros
- `diesel` - Diesel support (experimental)

Runtimes:

- `sync` (default) - Synchronous API
- `sync-tls` - TLS support for Synchronous API
- `tokio` (default) - Asynchronous API using tokio
- `tokio-tls` - TLS support for tokio
- `compio` - Asynchronous API using compio (experimental)
- `compio-tls` - TLS support for compio (experimental)

[External type supports](https://rusticdotdev.github.io/zero-postgres/type_conversion.html#feature-gated-types):

- `with-jiff` - Support [jiff](https://crates.io/crates/jiff) types
- `with-time` - Support [time](https://crates.io/crates/time) types
- `with-uuid` - Support [uuid](https://crates.io/crates/uuid) types
- `with-rust-decimal` - Support [rust_decimal](https://crates.io/crates/rust_decimal) types
- TODO: more decimal types

Other features:

- `auth-gss` - enable GSSAPI / SSPI authentication.
  Requires `libkrb5-dev`, `libclang-dev`, `pkg-config`

## Benchmark

Inserting 10,000 rows using prepared statements (average of 10 iterations):

| Library               | Avg Time (ms) |
| --------------------- | ------------- |
| zero-postgres (sync)  | 250.35        |
| zero-postgres (async) | 269.32        |
| tokio-postgres        | 398.90        |
| postgres (sync)       | 422.61        |

Run benchmarks: `cargo run --release --example bench_zero_sync`

See also [Diesel Benchmarks](https://github.com/diesel-rs/metrics).
