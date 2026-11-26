//! Test that a connection remains usable after an extended-query server error.
//!
//! Verifies the state machine drains to ReadyForQuery internally,
//! so the next query sees a clean protocol state.

#![cfg(feature = "compio")]
#![allow(clippy::panic_in_result_fn, clippy::shadow_unrelated)]

use zero_postgres::Error;
use zero_postgres::compio::Conn;

async fn get_conn() -> Result<Conn, Error> {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/postgres".to_string());
    Conn::new(db_url.as_str()).await
}

fn assert_nul_rejected<T>(result: Result<T, Error>, field: &str) {
    let err = result.err();
    let expected = format!("NUL byte in {field}");
    assert!(
        matches!(&err, Some(Error::InvalidUsage(message)) if *message == expected),
        "{err:?}"
    );
}

/// Statements the server rejects, with the SQLSTATE each must report.
/// Covers errors raised during Parse (42P01, 42703) and during Execute (22012).
const REJECTED: [(&str, &str); 3] = [
    ("SELECT $1::int FROM missing_table", "42P01"),
    ("SELECT missing_column, $1::int", "42703"),
    ("SELECT 1 / $1::int", "22012"),
];

#[compio::test]
async fn server_errors_leave_connection_usable() -> Result<(), Error> {
    let mut conn = get_conn().await?;

    for (sql, sqlstate) in REJECTED {
        let err = conn.exec_drop(sql, (0_i32,)).await.expect_err(sql);
        assert_eq!(err.sqlstate(), Some(sqlstate), "{sql}: {err}");
        let rows: Vec<(i32,)> = conn.exec_collect("SELECT $1::int", (7_i32,)).await?;
        assert_eq!(rows, [(7,)]);
    }

    let err = conn
        .query_drop("SELECT * FROM missing_table")
        .await
        .expect_err("simple query should fail");
    assert_eq!(err.sqlstate(), Some("42P01"), "{err}");
    conn.query_drop("SELECT 1").await?;
    Ok(())
}

#[compio::test]
async fn nul_byte_rejection_leaves_connection_usable() -> Result<(), Error> {
    let mut conn = get_conn().await?;

    assert_nul_rejected(conn.query_drop("SELECT 1\0; SELECT 2").await, "query");
    assert!(!conn.is_broken());
    let rows: Vec<(i32,)> = conn.query_collect("SELECT 1").await?;
    assert_eq!(rows, [(1,)]);

    assert_nul_rejected(conn.exec_drop("SELECT $1::int\0", (1_i32,)).await, "query");
    assert!(!conn.is_broken());
    let rows: Vec<(i32,)> = conn.exec_collect("SELECT $1::int", (2_i32,)).await?;
    assert_eq!(rows, [(2,)]);

    assert_nul_rejected(conn.prepare("SELECT $1::int\0").await, "query");
    assert!(!conn.is_broken());
    let stmt = conn.prepare("SELECT $1::int").await?;
    let rows: Vec<(i32,)> = conn.exec_collect(&stmt, (3_i32,)).await?;
    assert_eq!(rows, [(3,)]);

    assert_nul_rejected(
        conn.lowlevel_bind("por\0tal", &stmt.wire_name(), (4_i32,))
            .await,
        "portal name",
    );
    assert!(!conn.is_broken());
    let rows: Vec<(i32,)> = conn.exec_collect(&stmt, (5_i32,)).await?;
    assert_eq!(rows, [(5,)]);
    conn.query_drop("SELECT 1").await?;
    Ok(())
}
