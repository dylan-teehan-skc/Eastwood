#ifndef SCHEMA_H
#define SCHEMA_H
#include <iostream>
#include <sqlite3.h>

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
)sql";

    const auto &db = Database::get();
    char *errmsg = nullptr;
    if (const int rc = sqlite3_exec(db.getDatabase(), schema_sql, nullptr, nullptr, &errmsg); rc != SQLITE_OK) {
        std::cerr << "Failed to create schema: " << errmsg << std::endl;
        sqlite3_free(errmsg);
        throw std::runtime_error("Schema creation failed");
    }
}

#endif //SCHEMA_H
