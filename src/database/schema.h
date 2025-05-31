#ifndef SCHEMA_H
#define SCHEMA_H
#include <iostream>
#include <sqlite3.h>
#include <set>


#include "database.h"

inline void init_schema() {
    const auto schema_sql = R"sql(
    CREATE TABLE IF NOT EXISTS keypairs (
        label                 TEXT PRIMARY KEY,
        public_key            BLOB UNIQUE,
        encrypted_private_key BLOB UNIQUE,
        nonce                 BLOB UNIQUE,
        created_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_modified         DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS keypairs_public_key_idx ON keypairs (public_key);

    CREATE TRIGGER IF NOT EXISTS keypairs_last_modified_trigger
    AFTER UPDATE ON keypairs
    FOR EACH ROW
    BEGIN
        UPDATE keypairs SET last_modified = CURRENT_TIMESTAMP WHERE label = OLD.label;
    END;

    CREATE TABLE IF NOT EXISTS keys (
        label         TEXT PRIMARY KEY,
        encrypted_key BLOB UNIQUE,
        nonce         BLOB UNIQUE,
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TRIGGER IF NOT EXISTS keys_last_modified_trigger
    AFTER UPDATE ON keys
    FOR EACH ROW
    BEGIN
        UPDATE keys SET last_modified = CURRENT_TIMESTAMP WHERE label = OLD.label;
    END;

    CREATE TABLE IF NOT EXISTS onetime_prekeys (
        public_key BLOB PRIMARY KEY,
        encrypted_key BLOB UNIQUE,
        nonce BLOB UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TRIGGER IF NOT EXISTS onetime_keys_last_modified_trigger
    AFTER UPDATE ON onetime_prekeys
    FOR EACH ROW
    BEGIN
        UPDATE onetime_prekeys SET last_modified = CURRENT_TIMESTAMP WHERE onetime_prekey_id = OLD.onetime_prekey_id;
    END;

    CREATE TABLE IF NOT EXISTS file_keys (
        file_uuid       VARCHAR(36) PRIMARY KEY,
        encrypted_key BLOB UNIQUE,
        nonce         BLOB UNIQUE,
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TRIGGER IF NOT EXISTS file_keys_last_modified_trigger
    AFTER UPDATE ON file_keys
    FOR EACH ROW
    BEGIN
        UPDATE file_keys SET last_modified = CURRENT_TIMESTAMP WHERE label = OLD.label;
    END;

    CREATE TABLE IF NOT EXISTS ratchets (
        ratchet_id       BLOB PRIMARY KEY,
        identity_session_id BLOB UNIQUE,
        nonce         BLOB UNIQUE,
        encrypted_data         BLOB UNIQUE,
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TRIGGER IF NOT EXISTS ratchets_last_modified_trigger
    AFTER UPDATE ON ratchets
    FOR EACH ROW
    BEGIN
        UPDATE ratchets SET last_modified = CURRENT_TIMESTAMP WHERE label = OLD.label;
    END;

    CREATE TABLE IF NOT EXISTS ratchet_keys (
        ratchet_id       BLOB PRIMARY KEY,
        nonce         BLOB UNIQUE,
        encrypted_key         BLOB UNIQUE,
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TRIGGER IF NOT EXISTS ratchet_keys_last_modified_trigger
    AFTER UPDATE ON ratchet_keys
    FOR EACH ROW
    BEGIN
        UPDATE ratchet_keys SET last_modified = CURRENT_TIMESTAMP WHERE label = OLD.label;
    END;
)sql";

    const auto &db = Database::get();
    char *errmsg = nullptr;
    if (const int rc = sqlite3_exec(db.getDatabase(), schema_sql, nullptr, nullptr, &errmsg); rc != SQLITE_OK) {
        std::cerr << "Failed to create schema: " << errmsg << std::endl;
        sqlite3_free(errmsg);
        throw std::runtime_error("Schema creation failed");
    }
}

inline void drop_all_tables() {
    if (!Database::get().isInitialized()) {
        return;
    }
    std::cerr << "DROPPING ALL TABLES" << std::endl;
    const auto &db = Database::get();
    sqlite3 *sqlite = db.getDatabase();
    const auto sql = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';";
    sqlite3_stmt *stmt = nullptr;
    std::set<std::string> tables;
    if (sqlite3_prepare_v2(sqlite, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const auto name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
            if (name) tables.insert(name);
        }
        sqlite3_finalize(stmt);
    } else {
        std::cerr << "Failed to query tables: " << sqlite3_errmsg(sqlite) << std::endl;
        return;
    }
    for (const auto &table: tables) {
        std::string drop_sql = "DROP TABLE IF EXISTS '" + table + "';";
        char *errmsg = nullptr;
        if (sqlite3_exec(sqlite, drop_sql.c_str(), nullptr, nullptr, &errmsg) != SQLITE_OK) {
            std::cerr << "Failed to drop table " << table << ": " << errmsg << std::endl;
            sqlite3_free(errmsg);
        }
    }
}

#endif //SCHEMA_H
