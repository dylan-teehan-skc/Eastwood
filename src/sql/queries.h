//
// Created by Fred Sheppard on 27/05/2025.
//

#ifndef QUERIES_H
#define QUERIES_H

#include <tuple>
#include "src/algorithms/constants.h"
#include <iostream>

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

inline std::tuple<QByteArray, std::unique_ptr<SecureMemoryBuffer> > get_decrypted_keypair(const std::string &label) {
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
    return decrypt_symmetric_key(q_byte_array_to_chars(encrypted_key), q_byte_array_to_chars(nonce));
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

inline void save_encrypted_onetime_keys(
    const std::vector<std::tuple<unsigned char *, std::unique_ptr<SecureMemoryBuffer>, unsigned char *> > &onetime_keys
) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;

    for (const auto &[pk, encrypted_sk, nonce]: onetime_keys) {
        try {
            db.prepare_or_throw(
                "INSERT INTO onetime_prekeys (public_key, encrypted_key, nonce) VALUES (?, ?, ?);", &stmt
            );

            if (!pk || !encrypted_sk || !nonce) {
                std::cerr << "Invalid key data" << std::endl;
                continue;
            }

            sqlite3_bind_blob(stmt, 1, pk, crypto_box_PUBLICKEYBYTES, SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 2, encrypted_sk->data(), encrypted_sk->size(), SQLITE_TRANSIENT);
            sqlite3_bind_blob(stmt, 3, nonce, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);

            db.execute(stmt);
        } catch (const std::exception &e) {
            std::cerr << "Error saving one-time key" << std::endl;
        }
    }
    std::cout << "Finished processing all one-time keys" << std::endl;
}

inline std::unique_ptr<SecureMemoryBuffer> get_onetime_private_key(const unsigned char *public_key = nullptr) {
    if (!public_key) {
        return nullptr;
    }
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "SELECT encrypted_key, nonce FROM onetime_prekeys WHERE public_key = ?",
        &stmt
    );
    sqlite3_bind_blob(stmt, 1, public_key, crypto_box_PUBLICKEYBYTES, SQLITE_TRANSIENT);

    auto rows = db.query(stmt);
    if (rows.empty()) {
        return nullptr;
    }

    const auto &row = rows[0];
    QByteArray encrypted_key = row["encrypted_key"].toByteArray();
    QByteArray nonce = row["nonce"].toByteArray();

    // Decrypt the private key
    auto decrypted_key = decrypt_secret_key(
        q_byte_array_to_chars(encrypted_key),
        q_byte_array_to_chars(nonce)
    );

    return decrypted_key;
}

inline void save_encrypted_file_key(
    const std::string &file_uuid,
    const std::unique_ptr<SecureMemoryBuffer> &encrypted_key,
    const unsigned char nonce_sk[CHA_CHA_NONCE_LEN]
) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "INSERT INTO file_keys (file_uuid, encrypted_key, nonce) VALUES (?, ?, ?);", &stmt
    );
    sqlite3_bind_text(stmt, 1, file_uuid.data(), file_uuid.size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, encrypted_key->data(), encrypted_key->size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, nonce_sk, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);
    db.execute(stmt);
}


inline std::unique_ptr<SecureMemoryBuffer> get_decrypted_file_key(
    const std::string &file_uuid
) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "SELECT encrypted_key, nonce FROM file_keys WHERE file_uuid = ?;", &stmt
    );
    sqlite3_bind_text(stmt, 1, file_uuid.data(), file_uuid.size(), SQLITE_TRANSIENT);

    auto rows = db.query(stmt);
    if (rows.empty()) {
        throw std::runtime_error("Unable to find file for the given id. Check SQL logs");
    }

    const auto &row = rows[0];
    const QByteArray encrypted_key = row["encrypted_key"].toByteArray();
    const QByteArray nonce = row["nonce"].toByteArray();

    // Decrypt the private key
    auto decrypted_key = decrypt_symmetric_key(
        q_byte_array_to_chars(encrypted_key),
        q_byte_array_to_chars(nonce)
    );

    return decrypted_key;
}

inline void save_ratchet_and_key(const unsigned char* ratchet_id, const unsigned char* identity_session_id, const std::vector<unsigned char> &encrypted_ratchet, const unsigned char* ratchet_nonce, const std::unique_ptr<SecureMemoryBuffer> &encrypted_key, const unsigned char* sk_nonce) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "INSERT OR REPLACE INTO ratchets (ratchet_id, identity_session_id, nonce, encrypted_data) VALUES (?, ?, ?, ?);", &stmt
    );
    sqlite3_bind_blob(stmt, 1, ratchet_id, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, identity_session_id, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, ratchet_nonce, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, encrypted_ratchet.data(), encrypted_ratchet.size(), SQLITE_TRANSIENT);
    db.execute(stmt);

    sqlite3_stmt *stmt2;
    db.prepare_or_throw(
        "INSERT OR REPLACE INTO ratchet_keys (ratchet_id, nonce, encrypted_key) VALUES (?, ?, ?);", &stmt2
    );
    sqlite3_bind_blob(stmt2, 1, ratchet_id, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt2, 2, sk_nonce, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt2, 3, encrypted_key.get()->data(), encrypted_key.get()->size(), SQLITE_TRANSIENT);
    db.execute(stmt2);
}

inline std::vector<unsigned char> get_decrypted_ratchet(const unsigned char* ratchet_id) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    
    // First get the encrypted ratchet data and its nonce
    db.prepare_or_throw(
        "SELECT encrypted_data, nonce FROM ratchets WHERE ratchet_id = ?;", &stmt
    );
    sqlite3_bind_blob(stmt, 1, ratchet_id, 32, SQLITE_TRANSIENT);
    
    auto rows = db.query(stmt);
    if (rows.empty()) {
        throw std::runtime_error("No ratchet found with the given ID");
    }
    
    const auto &row = rows[0];
    QByteArray encrypted_data = row["encrypted_data"].toByteArray();
    QByteArray ratchet_nonce = row["nonce"].toByteArray();
    
    sqlite3_stmt *stmt2;
    db.prepare_or_throw(
        "SELECT encrypted_key, nonce FROM ratchet_keys WHERE ratchet_id = ?;", &stmt2
    );
    sqlite3_bind_blob(stmt2, 1, ratchet_id, 32, SQLITE_TRANSIENT);
    
    auto key_rows = db.query(stmt2);
    if (key_rows.empty()) {
        throw std::runtime_error("No key found for the given ratchet ID");
    }
    
    const auto &key_row = key_rows[0];
    QByteArray encrypted_key = key_row["encrypted_key"].toByteArray();
    QByteArray key_nonce = key_row["nonce"].toByteArray();
    
    auto decrypted_key = decrypt_symmetric_key(
        q_byte_array_to_chars(encrypted_key),
        q_byte_array_to_chars(key_nonce)
    );
    
    auto decrypted_ratchet = decrypt_bytes(
        encrypted_data,
        decrypted_key,
        std::vector<unsigned char>(ratchet_nonce.begin(), ratchet_nonce.end())
    );
    
    return decrypted_ratchet;
}



#endif //QUERIES_H
