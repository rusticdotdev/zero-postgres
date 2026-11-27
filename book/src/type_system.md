# Type System

| OID range | Types in this range |
|-----------|---------------------|
| 1 to 9999 | Built-in types whose OID is written in the PostgreSQL source, such as `int4` (23) and `text` (25) |
| 10000 to 11999 | Row types of system catalog tables, such as `pg_attrdef`, and their array types |
| 12000 to 16383 | Row types of system views, such as `pg_roles`, and every type in `information_schema` |
| 16384 and above | Types created after the database is initialized, by `CREATE TYPE`, `CREATE TABLE`, or `CREATE EXTENSION`. The same type gets a different OID in each database. |

| `typtype` | Meaning | Examples |
|-----------|---------|----------|
| `b` (Base Type) | Base type. Array types are also `b`. | `int4`, `text`, `_int4` |
| `c` (Composite Type) | Composite type, such as the row type of a table | `pg_class` |
| `d` (Domain Type) | Domain over another type | `information_schema.cardinal_number` |
| `e` (Enum Type) | Enumerated type | None built in. `CREATE TYPE mood AS ENUM ('sad', 'ok')` creates one. |
| `r` (Range Type) | Range type | `int4range`, `tstzrange` |
| `m` (Multirange Type) | Multirange type | `int4multirange` |
| `p` (Pseudo-Type) | Pseudo-type | `record`, `void`, `anyelement` |

Counts over the 637 rows of [pg_type](pg_type.md):

| Column | Types with a function | Distinct functions |
|--------|-----------------------|--------------------|
| `typinput` (Text Encoding) | 637 | 100 |
| `typoutput` (Text Decoding) | 637 | 99 |
| `typreceive` (Binary Encoding) | 617 | 80 |
| `typsend` (Binary Decoding) | 617 | 79 |
