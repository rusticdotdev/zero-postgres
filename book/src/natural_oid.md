# Natural OID

| Rust | PG name (typname) | oid |
|---|---|---|
| `bool` | `bool` | `16` |
| `i8` | `int2` | `21` |
| `i16` | `int2` | `21` |
| `i32` | `int4` | `23` |
| `i64` | `int8` | `20` |
| `u8` | `int2` | `21` |
| `u16` | `int4` | `23` |
| `u32` | `int8` | `20` |
| `u64` | `int8` | `20` |
| `f32` | `float4` | `700` |
| `f64` | `float8` | `701` |
| `str` | `text` | `25` |
| `String` | `text` | `25` |
| `[u8]` | `bytea` | `17` |
| `Vec<u8>` | `bytea` | `17` |
| `&T` | Same as `T` | |
| `Option<T>` (`Some`) | Same as `T` | |
| `Option<T>` (`None`) | | `0` |
| `(T0, T1, ..)` **(TODO)** | `record` | `2249` |
| `[T]` **(TODO)** | `typarray` of `T` | |
| `Vec<T>` **(TODO)** | `typarray` of `T` | |
| `[T; N]` **(TODO)** | `typarray` of `T` | |

### `with-jiff` (`jiff` crate)

| Rust | PG name (typname) | oid |
|---|---|---|
| `jiff::civil::Date` | `date` | `1082` |
| `jiff::civil::Time` | `time` | `1083` |
| `jiff::civil::DateTime` | `timestamp` | `1114` |
| `jiff::Timestamp` | `timestamptz` | `1184` |
| `jiff::ZonedDateTime` | `timestamptz` | `1184` |
| `jiff::Span` | `interval` | `1186` |
| `jiff::SignedDuration` | `interval` | `1186` |

### `with-time` (`time` crate)

| Rust | PG name (typname) | oid |
|---|---|---|
| `time::Date` | `date` | `1082` |
| `time::Time` | `time` | `1083` |
| `time::PrimitiveDateTime` | `timestamp` | `1114` |
| `time::OffsetDateTime` | `timestamptz` | `1184` |
| `time::SignedDuration` | `interval` | `1186` |

### `with-uuid` (`uuid` crate)

| Rust | PG name (typname) | oid |
|---|---|---|
| `uuid::Uuid` | `uuid` | `2950` |

### `with-rust-decimal` (`rust_decimal` crate)

| Rust | PG name (typname) | oid |
|---|---|---|
| `rust_decimal::Decimal` | `numeric` | `1700` |
