use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

use crate::totp::EntrySpec;

#[derive(Debug, Clone)]
pub struct StoredEntry {
    pub id: i64,
    pub issuer: String,
    pub account: String,
    pub label: String,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
    pub algorithm: String,
    pub digits: u8,
    pub period: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create database directory {parent:?}"))?;
        }
    }
    let connection = Connection::open(path)
        .with_context(|| format!("failed to open SQLite database at {path:?}"))?;
    configure(&connection)?;
    migrate(&connection)?;
    Ok(connection)
}

pub fn configure(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
}

pub fn migrate(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash BLOB NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

        CREATE TABLE IF NOT EXISTS totp_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issuer TEXT NOT NULL,
            account TEXT NOT NULL,
            label TEXT NOT NULL,
            secret_ciphertext BLOB NOT NULL,
            secret_nonce BLOB NOT NULL,
            algorithm TEXT NOT NULL DEFAULT 'SHA1',
            digits INTEGER NOT NULL DEFAULT 6,
            period INTEGER NOT NULL DEFAULT 30,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_totp_entries_sort
            ON totp_entries(issuer COLLATE NOCASE, label COLLATE NOCASE, account COLLATE NOCASE);",
    )
}

pub fn admin_password_hash(connection: &Connection) -> rusqlite::Result<Option<String>> {
    connection
        .query_row("SELECT password_hash FROM admin WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()
}

pub fn insert_admin(
    connection: &Connection,
    password_hash: &str,
    now: i64,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO admin (id, password_hash, created_at, updated_at) VALUES (1, ?1, ?2, ?2)",
        params![password_hash, now],
    )?;
    Ok(())
}

pub fn update_admin_password(
    connection: &Connection,
    password_hash: &str,
    now: i64,
) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE admin SET password_hash = ?1, updated_at = ?2 WHERE id = 1",
        params![password_hash, now],
    )?;
    Ok(())
}

pub fn create_session(
    connection: &Connection,
    token_hash: &[u8],
    created_at: i64,
    expires_at: i64,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO sessions (token_hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
        params![token_hash, created_at, expires_at],
    )?;
    Ok(())
}

pub fn session_is_valid(
    connection: &Connection,
    token_hash: &[u8],
    now: i64,
) -> rusqlite::Result<bool> {
    connection.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now])?;
    let found = connection
        .query_row(
            "SELECT 1 FROM sessions WHERE token_hash = ?1 AND expires_at > ?2",
            params![token_hash, now],
            |_row| Ok(()),
        )
        .optional()?;
    Ok(found.is_some())
}

pub fn delete_session(connection: &Connection, token_hash: &[u8]) -> rusqlite::Result<()> {
    connection.execute(
        "DELETE FROM sessions WHERE token_hash = ?1",
        params![token_hash],
    )?;
    Ok(())
}

pub fn all_entries(connection: &Connection) -> rusqlite::Result<Vec<StoredEntry>> {
    let mut statement = connection.prepare(
        "SELECT id, issuer, account, label, secret_ciphertext, secret_nonce,
                algorithm, digits, period, created_at, updated_at
         FROM totp_entries
         ORDER BY created_at ASC, id ASC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(StoredEntry {
            id: row.get(0)?,
            issuer: row.get(1)?,
            account: row.get(2)?,
            label: row.get(3)?,
            secret_ciphertext: row.get(4)?,
            secret_nonce: row.get(5)?,
            algorithm: row.get(6)?,
            digits: row.get(7)?,
            period: row.get(8)?,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
        })
    })?;
    rows.collect()
}

pub fn find_entry(connection: &Connection, id: i64) -> rusqlite::Result<Option<StoredEntry>> {
    let mut statement = connection.prepare(
        "SELECT id, issuer, account, label, secret_ciphertext, secret_nonce,
                algorithm, digits, period, created_at, updated_at
         FROM totp_entries WHERE id = ?1",
    )?;
    statement
        .query_row(params![id], |row| {
            Ok(StoredEntry {
                id: row.get(0)?,
                issuer: row.get(1)?,
                account: row.get(2)?,
                label: row.get(3)?,
                secret_ciphertext: row.get(4)?,
                secret_nonce: row.get(5)?,
                algorithm: row.get(6)?,
                digits: row.get(7)?,
                period: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })
        .optional()
}

pub fn insert_entry(
    connection: &Connection,
    entry: &EntrySpec,
    ciphertext: &[u8],
    nonce: &[u8],
    now: i64,
) -> rusqlite::Result<i64> {
    connection.execute(
        "INSERT INTO totp_entries
         (issuer, account, label, secret_ciphertext, secret_nonce, algorithm, digits, period, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
        params![
            entry.issuer,
            entry.account,
            entry.label,
            ciphertext,
            nonce,
            entry.algorithm,
            entry.digits,
            entry.period,
            now,
        ],
    )?;
    Ok(connection.last_insert_rowid())
}

pub fn update_entry(
    connection: &Connection,
    id: i64,
    entry: &EntrySpec,
    encrypted_secret: Option<(&[u8], &[u8])>,
    now: i64,
) -> rusqlite::Result<bool> {
    let changed = if let Some((ciphertext, nonce)) = encrypted_secret {
        connection.execute(
            "UPDATE totp_entries SET issuer = ?1, account = ?2, label = ?3,
             secret_ciphertext = ?4, secret_nonce = ?5, algorithm = ?6, digits = ?7,
             period = ?8, updated_at = ?9 WHERE id = ?10",
            params![
                entry.issuer,
                entry.account,
                entry.label,
                ciphertext,
                nonce,
                entry.algorithm,
                entry.digits,
                entry.period,
                now,
                id,
            ],
        )?
    } else {
        connection.execute(
            "UPDATE totp_entries SET issuer = ?1, account = ?2, label = ?3,
             algorithm = ?4, digits = ?5, period = ?6, updated_at = ?7 WHERE id = ?8",
            params![
                entry.issuer,
                entry.account,
                entry.label,
                entry.algorithm,
                entry.digits,
                entry.period,
                now,
                id,
            ],
        )?
    };
    Ok(changed > 0)
}

pub fn delete_entry(connection: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(connection.execute("DELETE FROM totp_entries WHERE id = ?1", params![id])? > 0)
}

pub fn insert_entries(
    connection: &mut Connection,
    entries: &[(EntrySpec, Vec<u8>, Vec<u8>)],
    now: i64,
) -> rusqlite::Result<()> {
    let transaction = connection.transaction()?;
    for (entry, ciphertext, nonce) in entries {
        transaction.execute(
            "INSERT INTO totp_entries
             (issuer, account, label, secret_ciphertext, secret_nonce, algorithm, digits, period, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
            params![
                entry.issuer,
                entry.account,
                entry.label,
                ciphertext,
                nonce,
                entry.algorithm,
                entry.digits,
                entry.period,
                now,
            ],
        )?;
    }
    transaction.commit()
}

pub fn entry_periods(connection: &Connection) -> rusqlite::Result<Vec<u64>> {
    let mut statement = connection.prepare("SELECT period FROM totp_entries")?;
    let rows = statement.query_map([], |row| row.get::<_, u64>(0))?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::{configure, migrate};
    use rusqlite::Connection;

    #[test]
    fn creates_the_schema_in_an_empty_database() {
        let connection = Connection::open_in_memory().unwrap();
        configure(&connection).unwrap();
        migrate(&connection).unwrap();
        let count: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'totp_entries'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
