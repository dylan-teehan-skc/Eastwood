//
// Created by Fred Sheppard on 27/05/2025.
//

#ifndef QUERIES_H
#define QUERIES_H

#include <tuple>
#include "src/algorithms/constants.h"

#include "src/database/database.h"
#include "src/keys/secure_memory_buffer.h"
#include "src/algorithms/algorithms.h"
#include <memory>

#include "src/utils/ConversionUtils.h"


inline std::tuple<QByteArray, QByteArray, QByteArray> get_encrypted_keypair(const std::string &label) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw("SELECT public_key, encrypted_private_key, nonce FROM keypairs WHERE label = ?", &stmt);
    sqlite3_bind_text(stmt, 1, label.c_str(), static_cast<int>(label.length()), SQLITE_TRANSIENT);
    // Label is marked as unique - will always return at most one row
    auto rows = db.query(stmt);
    if (rows.empty()) {
        throw std::runtime_error("No keys found for label " + label);
    }
    const auto &row = rows[0];

    QByteArray publicKey = row["public_key"].toByteArray();
    QByteArray encryptedPrivateKey = row["encrypted_private_key"].toByteArray();
    QByteArray nonce = row["nonce"].toByteArray();
    return std::make_tuple(publicKey, encryptedPrivateKey, nonce);
}

inline std::tuple<QByteArray, std::unique_ptr<SecureMemoryBuffer>> get_decrypted_keypair(const std::string &label) {
    auto [public_key, encrypted_sk, nonce] = get_encrypted_keypair(label);
    auto secret_key = decrypt_secret_key(q_byte_array_to_chars(encrypted_sk), q_byte_array_to_chars(nonce));
    return std::make_tuple(public_key, std::move(secret_key));
}

inline QByteArray get_public_key(const std::string &label) {
    auto [publicKey, _, _1] = get_encrypted_keypair(label);
    return publicKey;
}

inline std::unique_ptr<SecureMemoryBuffer> get_decrypted_sk(const std::string &label) {
    auto [_, sk] = get_decrypted_keypair(label);
    return std::move(sk);
};

inline void save_encrypted_keypair(
    const std::string &label,
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES],
    const std::unique_ptr<SecureMemoryBuffer> &encrypted_sk,
    unsigned char nonce[CHA_CHA_NONCE_LEN]
) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "INSERT INTO keypairs (label, public_key, encrypted_private_key, nonce) VALUES (?, ?, ?, ?);", &stmt
    );
    sqlite3_bind_text(stmt, 1, label.c_str(), static_cast<int>(label.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, public_key, crypto_sign_PUBLICKEYBYTES, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, encrypted_sk->data(), encrypted_sk->size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, nonce, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);
    db.execute(stmt);
}

inline std::tuple<QByteArray, QByteArray> get_encrypted_key(
    const std::string &label
) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw("SELECT encrypted_key, nonce FROM keys WHERE label = ?", &stmt);
    sqlite3_bind_text(stmt, 1, label.c_str(), static_cast<int>(label.length()), SQLITE_TRANSIENT);
    auto rows = db.query(stmt);
    if (rows.empty()) {
        throw std::runtime_error("No keys found for label " + label);
    }
    // Label is marked as unique - will always return at most one row
    const auto &row = rows[0];

    QByteArray encryptedKey = row["encrypted_key"].toByteArray();
    QByteArray nonce = row["nonce"].toByteArray();

    return std::make_tuple(encryptedKey, nonce);
}

inline std::unique_ptr<SecureMemoryBuffer> get_decrypted_key(const std::string &label) {
    const auto [encrypted_key, nonce] = get_encrypted_key(label);
    return decrypt_key(q_byte_array_to_chars(encrypted_key), q_byte_array_to_chars(nonce));
};

inline void save_encrypted_key(
    const std::string &label,
    const std::unique_ptr<SecureMemoryBuffer> &encrypted_key,
    const unsigned char nonce_sk[CHA_CHA_NONCE_LEN]
) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "INSERT INTO keys (label, encrypted_key, nonce) VALUES (?, ?, ?);", &stmt
    );
    sqlite3_bind_text(stmt, 1, label.c_str(), static_cast<int>(label.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, encrypted_key->data(), encrypted_key->size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, nonce_sk, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);
    db.execute(stmt);
}


#endif //QUERIES_H
