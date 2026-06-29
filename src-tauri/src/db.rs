//! SQLite connection setup and schema migrations.

use rusqlite::Connection;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Result;

/// Ordered list of migrations. Each entry: (version, SQL).
const MIGRATIONS: &[(&str, &str)] = &[("001", include_str!("../migrations/001_initial.sql"))];

/// Current unix time in milliseconds.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Apply the standard PRAGMAs used by the app.
fn apply_pragmas(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    Ok(())
}

/// Open (creating if needed) a vault DB at `path`, apply pragmas, run migrations.
pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    run_migrations(&conn)?;
    Ok(conn)
}

/// Open an in-memory DB (used by tests).
pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    // WAL is not meaningful in-memory; just enable FKs.
    conn.pragma_update(None, "foreign_keys", "ON")?;
    run_migrations(&conn)?;
    Ok(conn)
}

/// Run any migrations newer than the stored `db_version`.
pub fn run_migrations(conn: &Connection) -> Result<()> {
    // The meta table must exist before we can read db_version; the first
    // migration creates it with IF NOT EXISTS, so apply migrations idempotently
    // and track the highest applied version.
    let current = current_version(conn).unwrap_or(None);

    for (version, sql) in MIGRATIONS {
        let already = match &current {
            Some(v) => version <= &v.as_str(),
            None => false,
        };
        if already {
            continue;
        }
        conn.execute_batch(sql)?;
        conn.execute(
            "INSERT INTO vault_meta(key, value) VALUES('db_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [version],
        )?;
    }
    Ok(())
}

/// Read the stored db schema version, if the meta table exists.
fn current_version(conn: &Connection) -> Result<Option<String>> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_meta'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !exists {
        return Ok(None);
    }
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key='db_version'",
            [],
            |r| r.get(0),
        )
        .ok();
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_create_tables() {
        let conn = open_in_memory().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('projects','secrets','tags','secret_tags','vault_meta')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn migrations_are_idempotent() {
        let conn = open_in_memory().unwrap();
        // Running again must not error.
        run_migrations(&conn).unwrap();
        let v: String = conn
            .query_row("SELECT value FROM vault_meta WHERE key='db_version'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "001");
    }
}
