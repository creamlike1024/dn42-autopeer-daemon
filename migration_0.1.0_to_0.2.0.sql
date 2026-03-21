-- Migration Script: v0.1.0 -> v0.2.0
-- 
-- Changes:
-- 1. Modified `wireguard_endpoint` column to be nullable (removed `NOT NULL` constraint).
-- 2. Added `wireguard_preshared_key` column as an optional `TEXT` field.
-- 
-- Usage: sqlite3 peers.db < migration_0.1.0_to_0.2.0.sql

PRAGMA foreign_keys=off;
BEGIN TRANSACTION;

-- Create the new table without NOT NULL constraint on wireguard_endpoint
-- and with the new wireguard_preshared_key column included
CREATE TABLE peers_new (
    asn                     INTEGER PRIMARY KEY,
    wireguard_endpoint      TEXT,
    wireguard_link_local    TEXT NOT NULL,
    wireguard_public_key    TEXT NOT NULL,
    wireguard_preshared_key TEXT,
    mtu                     INTEGER NOT NULL,
    interface_name          TEXT NOT NULL,
    wireguard_config_path   TEXT NOT NULL,
    bird_config_path        TEXT NOT NULL
);

-- Copy the data from the old table to the new table
INSERT INTO peers_new (
    asn, 
    wireguard_endpoint, 
    wireguard_link_local, 
    wireguard_public_key, 
    mtu, 
    interface_name, 
    wireguard_config_path, 
    bird_config_path
)
SELECT 
    asn, 
    wireguard_endpoint, 
    wireguard_link_local, 
    wireguard_public_key, 
    mtu, 
    interface_name, 
    wireguard_config_path, 
    bird_config_path
FROM peers;

-- Drop the old table
DROP TABLE peers;

-- Rename the new table to the original table name
ALTER TABLE peers_new RENAME TO peers;

COMMIT;
PRAGMA foreign_keys=on;
