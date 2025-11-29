use crate::model::*;
use anyhow::Result;
use rusqlite::*;

#[derive(Debug)]
pub enum PeerDbError {
    NotFound,
    AlreadyExist,
    RusqliteError(rusqlite::Error),
    LockError(String),
}

impl std::fmt::Display for PeerDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerDbError::NotFound => write!(f, "Peer not found"),
            PeerDbError::AlreadyExist => write!(f, "Peer already exists"),
            PeerDbError::RusqliteError(err) => write!(f, "Rusqlite error: {}", err),
            PeerDbError::LockError(msg) => write!(f, "Mutex Lock error: {}", msg),
        }
    }
}

impl From<rusqlite::Error> for PeerDbError {
    fn from(error: rusqlite::Error) -> Self {
        if let rusqlite::Error::SqliteFailure(ref error_code, Some(ref message)) = error {
            if error_code.code == rusqlite::ErrorCode::ConstraintViolation
                && message.contains("UNIQUE constraint failed")
            {
                return PeerDbError::AlreadyExist;
            }
        } else if let rusqlite::Error::QueryReturnedNoRows = error {
            return PeerDbError::NotFound;
        }
        PeerDbError::RusqliteError(error)
    }
}

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, rusqlite::Connection>>> for PeerDbError {
    fn from(err: std::sync::PoisonError<std::sync::MutexGuard<'_, rusqlite::Connection>>) -> Self {
        PeerDbError::LockError(err.to_string())
    }
}

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS peers (
            asn                 INTEGER PRIMARY KEY,
            wireguard_endpoint  TEXT NOT NULL,
            wireguard_link_local TEXT NOT NULL,
            wireguard_public_key TEXT NOT NULL,
            interface_name TEXT NOT NULL,
            wireguard_config_path TEXT NOT NULL,
            bird_config_path TEXT NOT NULL
        )",
        (),
    )?;
    Ok(())
}

pub fn add_peer(conn: &Connection, peer: &Peer) -> Result<usize, PeerDbError> {
    let result = conn.execute(
        "INSERT INTO peers (asn, wireguard_endpoint, wireguard_link_local, wireguard_public_key, interface_name, wireguard_config_path, bird_config_path)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            peer.asn,
            peer.wireguard_endpoint,
            peer.wireguard_link_local,
            peer.wireguard_public_key,
            peer.gen_interface_name(),
            peer.gen_wireguard_config_path(),
            peer.gen_bird_config_path()
        ],
    );

    result.map_err(Into::into)
}

pub fn get_peer_by_asn(conn: &Connection, asn: u64) -> Result<PeerDbInfo, PeerDbError> {
    let peer = conn.query_row(
        "SELECT asn, wireguard_endpoint, wireguard_link_local, wireguard_public_key, interface_name, wireguard_config_path, bird_config_path FROM peers WHERE asn = ?1",
        rusqlite::params![asn],
        |row| {
            Ok(PeerDbInfo {
                asn: row.get(0)?,
                wireguard_endpoint: row.get(1)?,
                wireguard_link_local: row.get(2)?,
                wireguard_public_key: row.get(3)?,
                interface_name: row.get(4)?,
                wireguard_config_path: row.get(5)?,
                bird_config_path: row.get(6)?
            })
        },
    );

    match peer {
        Ok(p) => Ok(p),
        Err(e) => Err(e.into()),
    }
}

// usize 为受影响行数
pub fn delete_peer_by_asn(conn: &Connection, asn: u64) -> Result<usize, PeerDbError> {
    let rows_affected = conn.execute("DELETE FROM peers WHERE asn = ?1", rusqlite::params![asn])?;

    if rows_affected == 0 {
        return Err(PeerDbError::NotFound);
    }
    Ok(rows_affected)
}
