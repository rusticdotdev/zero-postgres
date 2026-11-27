# Type Conversion

## Number

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
| `bool` | `bool` (`BOOLEAN`) | same as input |
| `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64` | `int2` (`SMALLINT`) | `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64`, `f32`, `f64` |
| `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64` | `int4` (`INTEGER`) | `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64`, `f32`, `f64` |
| `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64` | `int8` (`BIGINT`) | `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64`, `f32`, `f64` |
| `f32`, `f64`, `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64` | `float4` (`REAL`) | `f32`, `f64` |
| `f32`, `f64`, `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, `u32`, `u64` | `float8` (`DOUBLE PRECISION`) | `f64` |
| `f32`, `f64`, `rust_decimal::Decimal` | `numeric` (`DECIMAL`) | `f32`, `f64`, `&str`, `String`, `rust_decimal::Decimal` |
|  | `money` |  |

## String

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
| `str`, `String` | `text` | `&str`, `String` |
| `str`, `String` | `varchar` (`CHARACTER VARYING`) | `&str`, `String` |
| `str`, `String` | `bpchar` (`CHARACTER`) | `&str`, `String` |
| `str`, `String` | `name` | `&str`, `String` |
| `i8`, `u8` | `char` | same as input |
| `[u8]`, `Vec<u8>` | `bytea` | `&[u8]`, `Vec<u8>` |

## Date, Time

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
| `jiff::civil::Date`, `time::Date` | `date` | same as input |
| `jiff::civil::Time`, `time::Time` | `time` (`TIME WITHOUT TIME ZONE`) | same as input |
|  | `timetz` (`TIME WITH TIME ZONE`) |  |
| `jiff::civil::DateTime`, `jiff::Timestamp`, `time::PrimitiveDateTime`, `time::OffsetDateTime` | `timestamp` (`TIMESTAMP WITHOUT TIME ZONE`) | `jiff::civil::DateTime`, `time::PrimitiveDateTime` |
| `std::time::SystemTime`, `jiff::civil::DateTime`, `jiff::Timestamp`, `jiff::ZonedDateTime`, `time::PrimitiveDateTime`, `time::OffsetDateTime` | `timestamptz` (`TIMESTAMP WITH TIME ZONE`) | same as input |
| `Interval`, `std::time::Duration`, `jiff::Span`, `jiff::SignedDuration`, `time::SignedDuration` | `interval` | same as input |

## UUID, JSON, XML

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
| `uuid::Uuid` | `uuid` | same as input |
| `str`, `String` | `json` | `&str`, `String` |
| `str`, `String` | `jsonb` | `&str`, `String` |
| `str`, `String` | `jsonpath` | `&str`, `String` |
|  | `xml` |  |

## Network, Bit String

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
| `(std::net::IpAddr, u8)` | `inet` | same as input |
| `(std::net::IpAddr, u8)` | `cidr` | same as input |
| `[u8; 6]` | `macaddr` | same as input |
| `[u8; 8]` | `macaddr8` | same as input |
|  | `bit` |  |
|  | `varbit` (`BIT VARYING`) |  |

## Geometric

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
|  | `point` |  |
|  | `line` |  |
|  | `lseg` |  |
|  | `box` |  |
|  | `path` |  |
|  | `polygon` |  |
|  | `circle` |  |

## Text Search

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
|  | `tsvector` |  |
|  | `tsquery` |  |
|  | `gtsvector` |  |

## Range, Multirange

`T` is a Rust type listed for the element type: `int4` for `int4range`, `int8` for `int8range`, `timestamp` for `tsrange`, `timestamptz` for `tstzrange`, `date` for `daterange`.

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
| `PgRange<T>`, `Range<T>`, `RangeInclusive<T>`, `RangeFrom<T>`, `RangeTo<T>`, `RangeToInclusive<T>` | `int4range` | same as input |
| `PgRange<T>`, `Range<T>`, `RangeInclusive<T>`, `RangeFrom<T>`, `RangeTo<T>`, `RangeToInclusive<T>` | `int8range` | same as input |
|  | `numrange` |  |
| `PgRange<T>`, `Range<T>`, `RangeInclusive<T>`, `RangeFrom<T>`, `RangeTo<T>`, `RangeToInclusive<T>` | `tsrange` | same as input |
| `PgRange<T>`, `Range<T>`, `RangeInclusive<T>`, `RangeFrom<T>`, `RangeTo<T>`, `RangeToInclusive<T>` | `tstzrange` | same as input |
| `PgRange<T>`, `Range<T>`, `RangeInclusive<T>`, `RangeFrom<T>`, `RangeTo<T>`, `RangeToInclusive<T>` | `daterange` | same as input |
|  | `int4multirange` |  |
|  | `int8multirange` |  |
|  | `nummultirange` |  |
|  | `tsmultirange` |  |
|  | `tstzmultirange` |  |
|  | `datemultirange` |  |

## Array

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
|  | `_xml` |  |
|  | `_json` |  |
|  | `_pg_type` |  |
|  | `_pg_attribute` |  |
|  | `_xid8` |  |
|  | `_pg_proc` |  |
|  | `_pg_class` |  |
|  | `_line` |  |
|  | `_cidr` |  |
|  | `_circle` |  |
|  | `_macaddr8` |  |
|  | `_money` |  |
|  | `_bool` |  |
|  | `_bytea` |  |
|  | `_char` |  |
|  | `_name` |  |
|  | `_int2` |  |
|  | `_int2vector` |  |
|  | `_int4` |  |
|  | `_regproc` |  |
|  | `_text` |  |
|  | `_tid` |  |
|  | `_xid` |  |
|  | `_cid` |  |
|  | `_oidvector` |  |
|  | `_bpchar` |  |
|  | `_varchar` |  |
|  | `_int8` |  |
|  | `_point` |  |
|  | `_lseg` |  |
|  | `_path` |  |
|  | `_box` |  |
|  | `_float4` |  |
|  | `_float8` |  |
|  | `_polygon` |  |
|  | `_oid` |  |
|  | `_aclitem` |  |
|  | `_macaddr` |  |
|  | `_inet` |  |
|  | `_timestamp` |  |
|  | `_date` |  |
|  | `_time` |  |
|  | `_timestamptz` |  |
|  | `_interval` |  |
|  | `_numeric` |  |
|  | `_cstring` |  |
|  | `_timetz` |  |
|  | `_bit` |  |
|  | `_varbit` |  |
|  | `_refcursor` |  |
|  | `_regprocedure` |  |
|  | `_regoper` |  |
|  | `_regoperator` |  |
|  | `_regclass` |  |
|  | `_regtype` |  |
|  | `_record` |  |
|  | `_txid_snapshot` |  |
|  | `_uuid` |  |
|  | `_pg_lsn` |  |
|  | `_tsvector` |  |
|  | `_gtsvector` |  |
|  | `_tsquery` |  |
|  | `_regconfig` |  |
|  | `_regdictionary` |  |
|  | `_jsonb` |  |
|  | `_int4range` |  |
|  | `_numrange` |  |
|  | `_tsrange` |  |
|  | `_tstzrange` |  |
|  | `_daterange` |  |
|  | `_int8range` |  |
|  | `_jsonpath` |  |
|  | `_regnamespace` |  |
|  | `_regrole` |  |
|  | `_regcollation` |  |
|  | `_pg_snapshot` |  |
|  | `_int4multirange` |  |
|  | `_nummultirange` |  |
|  | `_tsmultirange` |  |
|  | `_tstzmultirange` |  |
|  | `_datemultirange` |  |
|  | `_int8multirange` |  |
|  | `_oid8` |  |
|  | `_regdatabase` |  |

## System

| Rust (Input) | PostgreSQL | Rust (Output) |
|---|---|---|
|  | `oid` |  |
|  | `oid8` |  |
|  | `regproc` |  |
|  | `regprocedure` |  |
|  | `regoper` |  |
|  | `regoperator` |  |
|  | `regclass` |  |
|  | `regtype` |  |
|  | `regrole` |  |
|  | `regnamespace` |  |
|  | `regconfig` |  |
|  | `regdictionary` |  |
|  | `regcollation` |  |
|  | `regdatabase` |  |
|  | `xid` |  |
|  | `xid8` |  |
|  | `cid` |  |
|  | `tid` |  |
|  | `pg_lsn` |  |
|  | `txid_snapshot` |  |
|  | `pg_snapshot` |  |
|  | `int2vector` |  |
|  | `oidvector` |  |
|  | `aclitem` |  |
|  | `refcursor` |  |
|  | `pg_node_tree` |  |
|  | `pg_ndistinct` |  |
|  | `pg_dependencies` |  |
|  | `pg_mcv_list` |  |
|  | `pg_brin_bloom_summary` |  |
|  | `pg_brin_minmax_multi_summary` |  |
|  | `pg_type` |  |
|  | `pg_attribute` |  |
|  | `pg_proc` |  |
|  | `pg_class` |  |
|  | `pg_database` |  |
|  | `pg_parameter_acl` |  |
|  | `pg_authid` |  |
|  | `pg_auth_members` |  |
|  | `pg_shseclabel` |  |
|  | `pg_subscription` |  |
|  | `pg_ddl_command` |  |
|  | `table_am_handler` |  |
|  | `index_am_handler` |  |
|  | `unknown` |  |
|  | `record` |  |
|  | `cstring` |  |
|  | `any` |  |
|  | `anyarray` |  |
|  | `void` |  |
|  | `trigger` |  |
|  | `language_handler` |  |
|  | `internal` |  |
|  | `anyelement` |  |
|  | `anynonarray` |  |
|  | `fdw_handler` |  |
|  | `tsm_handler` |  |
|  | `anyenum` |  |
|  | `anyrange` |  |
|  | `event_trigger` |  |
|  | `anymultirange` |  |
|  | `anycompatiblemultirange` |  |
|  | `anycompatible` |  |
|  | `anycompatiblearray` |  |
|  | `anycompatiblenonarray` |  |
|  | `anycompatiblerange` |  |
