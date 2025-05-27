//
// Created by Fred Sheppard on 27/05/2025.
//

#ifndef QUERIES_H
#define QUERIES_H

#include <tuple>
#include <sodium.h>
#include "src/algorithms/constants.h"

#include "src/database/database.h"


inline std::tuple<QByteArray, QByteArray> get_keypair(const std::string &label) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw("SELECT public_key, encrypted_private_key FROM keypairs WHERE label = ?", &stmt);
    sqlite3_bind_text(stmt, 1, label.c_str(), static_cast<int>(label.length()), SQLITE_TRANSIENT);
    // Label is marked as unique - will always return at most one row
    auto rows = db.query(stmt);
    if (rows.empty()) {
        throw std::runtime_error("No keys found for label " + label);
    }
    const auto &row = rows[0];

    QByteArray publicKey = row["public_key"].toByteArray();
    QByteArray encryptedPrivateKey = row["encrypted_private_key"].toByteArray();
    return std::make_tuple(publicKey, encryptedPrivateKey);
}

inline void save_keypair(
    const std::string &label,
    unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES],
    unsigned char encrypted_sk[crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD],
    unsigned char nonce_sk[NONCE_LEN]
) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "INSERT INTO keypairs (label, public_key, encrypted_private_key, nonce) VALUES (?, ?, ?, ?);", &stmt
    );
    sqlite3_bind_text(stmt, 1, label.c_str(), static_cast<int>(label.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, pk_identity, crypto_sign_PUBLICKEYBYTES, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, encrypted_sk, crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, nonce_sk, NONCE_LEN, SQLITE_TRANSIENT);
    db.execute(stmt);
}

inline void save_encrypted_key(
    const std::string &label,
    unsigned char encrypted_key[crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD],
    unsigned char nonce_sk[NONCE_LEN]
) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "INSERT INTO keys (label, encrypted_key, nonce) VALUES (?, ?, ?);", &stmt
    );
    sqlite3_bind_text(stmt, 1, label.c_str(), static_cast<int>(label.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, encrypted_key, crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, nonce_sk, NONCE_LEN, SQLITE_TRANSIENT);
    db.execute(stmt);
}


#endif //QUERIES_H
