//
// Created by Fred Sheppard on 27/05/2025.
//

#ifndef QUERIES_H
#define QUERIES_H

#include <tuple>
#include "src/algorithms/constants.h"
#include <iostream>
#include <set>

#include "src/database/database.h"
#include "src/keys/secure_memory_buffer.h"
#include "src/algorithms/algorithms.h"
#include <memory>
#include <qdatetime.h>

#include "src/utils/ConversionUtils.h"
#include "src/keys/session_token_manager.h"


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
        "INSERT OR REPLACE INTO keypairs (label, public_key, encrypted_private_key, nonce) VALUES (?, ?, ?, ?);", &stmt
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
        "INSERT OR REPLACE INTO keys (label, encrypted_key, nonce) VALUES (?, ?, ?);", &stmt
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

// New function using username and device_id
inline void save_ratchet_and_key_by_username_device(const std::string& username, const std::array<unsigned char, 32>& device_id, const std::vector<unsigned char> &encrypted_ratchet, const unsigned char* ratchet_nonce, const std::unique_ptr<SecureMemoryBuffer> &encrypted_key, const unsigned char* sk_nonce) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "INSERT OR REPLACE INTO ratchets (username, device_id, nonce, encrypted_data) VALUES (?, ?, ?, ?);", &stmt
    );
    sqlite3_bind_text(stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, device_id.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, ratchet_nonce, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, encrypted_ratchet.data(), encrypted_ratchet.size(), SQLITE_TRANSIENT);
    db.execute(stmt);

    sqlite3_stmt *stmt2;
    db.prepare_or_throw(
        "INSERT OR REPLACE INTO ratchet_keys (username, device_id, nonce, encrypted_key) VALUES (?, ?, ?, ?);", &stmt2
    );
    sqlite3_bind_text(stmt2, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt2, 2, device_id.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt2, 3, sk_nonce, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt2, 4, encrypted_key.get()->data(), encrypted_key.get()->size(), SQLITE_TRANSIENT);
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
    
    auto decrypted_ratchet = decrypt_message_with_nonce(
        encrypted_data,
        decrypted_key,
        std::vector<unsigned char>(ratchet_nonce.begin(), ratchet_nonce.end())
    );
    
    return decrypted_ratchet;
}

// New function using username and device_id
inline std::vector<unsigned char> get_decrypted_ratchet_by_username_device(const std::string& username, const std::array<unsigned char, 32>& device_id) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    
    // First get the encrypted ratchet data and its nonce
    db.prepare_or_throw(
        "SELECT encrypted_data, nonce FROM ratchets WHERE username = ? AND device_id = ?;", &stmt
    );
    sqlite3_bind_text(stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, device_id.data(), 32, SQLITE_TRANSIENT);
    
    auto rows = db.query(stmt);
    if (rows.empty()) {
        throw std::runtime_error("No ratchet found for the given username and device_id");
    }
    
    const auto &row = rows[0];
    QByteArray encrypted_data = row["encrypted_data"].toByteArray();
    QByteArray ratchet_nonce = row["nonce"].toByteArray();
    
    sqlite3_stmt *stmt2;
    db.prepare_or_throw(
        "SELECT encrypted_key, nonce FROM ratchet_keys WHERE username = ? AND device_id = ?;", &stmt2
    );
    sqlite3_bind_text(stmt2, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt2, 2, device_id.data(), 32, SQLITE_TRANSIENT);
    
    auto key_rows = db.query(stmt2);
    if (key_rows.empty()) {
        throw std::runtime_error("No key found for the given username and device_id");
    }
    
    const auto &key_row = key_rows[0];
    QByteArray encrypted_key = key_row["encrypted_key"].toByteArray();
    QByteArray key_nonce = key_row["nonce"].toByteArray();
    
    auto decrypted_key = decrypt_symmetric_key(
        q_byte_array_to_chars(encrypted_key),
        q_byte_array_to_chars(key_nonce)
    );
    
    auto decrypted_ratchet = decrypt_message_with_nonce(
        encrypted_data,
        decrypted_key,
        std::vector<unsigned char>(ratchet_nonce.begin(), ratchet_nonce.end())
    );
    
    return decrypted_ratchet;
}

// Function to save encrypted message and its encryption key
inline void save_message_and_key(
    const std::string& username, 
    const std::array<unsigned char, 32>& from_device_id, 
    const std::string& file_uuid,
    const std::vector<unsigned char>& encrypted_message,
    const unsigned char* message_nonce, 
    const std::unique_ptr<SecureMemoryBuffer>& encrypted_key, 
    const unsigned char* key_nonce,
    bool sender = false
) {
    const auto &db = Database::get();
    
    // Save encrypted message
    sqlite3_stmt *stmt;
    db.prepare_or_throw(
        "INSERT OR REPLACE INTO messages (username, from_device_id, file_uuid, nonce, encrypted_message, is_sender) VALUES (?, ?, ?, ?, ?, ?);", &stmt
    );
    sqlite3_bind_text(stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, from_device_id.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 4, message_nonce, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, encrypted_message.data(), encrypted_message.size(), SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, sender ? 1: 0);
    db.execute(stmt);

    // Save encrypted key
    sqlite3_stmt *stmt2;
    db.prepare_or_throw(
        "INSERT OR REPLACE INTO message_keys (username, device_id, file_uuid, nonce, encrypted_key) VALUES (?, ?, ?, ?, ?);", &stmt2
    );
    sqlite3_bind_text(stmt2, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt2, 2, from_device_id.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt2, 3, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt2, 4, key_nonce, CHA_CHA_NONCE_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt2, 5, encrypted_key->data(), encrypted_key->size(), SQLITE_TRANSIENT);
    db.execute(stmt2);
}

// Function to retrieve and decrypt a message by file_uuid
inline std::vector<unsigned char> get_decrypted_message(const std::string& file_uuid) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    
    std::cout << "\n--- DEBUG: get_decrypted_message for UUID: " << file_uuid << " ---" << std::endl;
    
    // Get the encrypted message data and its nonce
    db.prepare_or_throw(
        "SELECT encrypted_message, nonce FROM messages WHERE file_uuid = ?;", &stmt
    );
    sqlite3_bind_text(stmt, 1, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
    
    auto rows = db.query(stmt);
    if (rows.empty()) {
        std::cout << "DEBUG: No message found in messages for UUID: " << file_uuid << std::endl;
        throw std::runtime_error("No message found with the given file_uuid");
    }
    
    const auto &row = rows[0];
    QByteArray encrypted_message = row["encrypted_message"].toByteArray();
    QByteArray message_nonce = row["nonce"].toByteArray();
    
    std::cout << "DEBUG: Found encrypted message in DB" << std::endl;
    std::cout << "Encrypted message size: " << encrypted_message.size() << " bytes" << std::endl;
    std::cout << "Message nonce size: " << message_nonce.size() << " bytes" << std::endl;
    std::cout << "Encrypted message first 16 bytes: ";
    for (int i = 0; i < std::min(static_cast<qsizetype>(16), encrypted_message.size()); i++) {
        printf("%02x ", static_cast<unsigned char>(encrypted_message[i]));
    }
    std::cout << std::endl;
    
    // Get the corresponding encryption key
    sqlite3_stmt *key_stmt;
    db.prepare_or_throw(
        "SELECT encrypted_key, nonce FROM message_keys WHERE file_uuid = ?;", &key_stmt
    );
    sqlite3_bind_text(key_stmt, 1, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
    
    auto key_rows = db.query(key_stmt);
    if (key_rows.empty()) {
        std::cout << "DEBUG: No key found in message_keys for UUID: " << file_uuid << std::endl;
        throw std::runtime_error("No key found for the given file_uuid");
    }
    
    const auto &key_row = key_rows[0];
    QByteArray encrypted_key = key_row["encrypted_key"].toByteArray();
    QByteArray key_nonce = key_row["nonce"].toByteArray();
    
    std::cout << "DEBUG: Found encryption key in DB" << std::endl;
    std::cout << "Encrypted key size: " << encrypted_key.size() << " bytes" << std::endl;
    std::cout << "Key nonce size: " << key_nonce.size() << " bytes" << std::endl;
    
    // Decrypt the symmetric key using KEK
    auto decrypted_key = decrypt_symmetric_key(
        q_byte_array_to_chars(encrypted_key),
        q_byte_array_to_chars(key_nonce)
    );
    
    std::cout << "DEBUG: Decrypted symmetric key" << std::endl;
    std::cout << "Decrypted key size: " << decrypted_key->size() << " bytes" << std::endl;
    std::cout << "Decrypted key first 8 bytes: ";
    for (size_t i = 0; i < std::min((size_t)8, decrypted_key->size()); i++) {
        printf("%02x ", decrypted_key->data()[i]);
    }
    std::cout << std::endl;
    
    // Decrypt the message using the decrypted symmetric key
    auto decrypted_message = decrypt_message_with_nonce(
        encrypted_message,
        decrypted_key,
        std::vector<unsigned char>(message_nonce.begin(), message_nonce.end())
    );
    
    std::cout << "DEBUG: Final decrypted message" << std::endl;
    std::cout << "Final decrypted message size: " << decrypted_message.size() << " bytes" << std::endl;
    if (!decrypted_message.empty()) {
        std::cout << "Final decrypted message first 8 bytes: ";
        for (size_t i = 0; i < std::min((size_t)8, decrypted_message.size()); i++) {
            printf("%02x ", decrypted_message[i]);
        }
        std::cout << std::endl;
    }
    
    return decrypted_message;
}

// Function to retrieve and decrypt a message by username and device_id
inline std::vector<unsigned char> get_decrypted_message_by_username_device(
    const std::string& username, 
    const std::array<unsigned char, 32>& from_device_id
) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    
    // Get the encrypted message data and its nonce
    db.prepare_or_throw(
        "SELECT encrypted_message, nonce, file_uuid FROM messages WHERE username = ? AND from_device_id = ?;", &stmt
    );
    sqlite3_bind_text(stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, from_device_id.data(), 32, SQLITE_TRANSIENT);
    
    auto rows = db.query(stmt);
    if (rows.empty()) {
        throw std::runtime_error("No message found for the given username and device_id");
    }
    
    const auto &row = rows[0];
    QByteArray encrypted_message = row["encrypted_message"].toByteArray();
    QByteArray message_nonce = row["nonce"].toByteArray();
    std::string file_uuid = row["file_uuid"].toString().toStdString();
    
    // Get the corresponding encryption key
    sqlite3_stmt *key_stmt;
    db.prepare_or_throw(
        "SELECT encrypted_key, nonce FROM message_keys WHERE username = ? AND device_id = ? AND file_uuid = ?;", &key_stmt
    );
    sqlite3_bind_text(key_stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(key_stmt, 2, from_device_id.data(), 32, SQLITE_TRANSIENT);
    sqlite3_bind_text(key_stmt, 3, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
    
    auto key_rows = db.query(key_stmt);
    if (key_rows.empty()) {
        throw std::runtime_error("No key found for the given username, device_id, and file_uuid");
    }
    
    const auto &key_row = key_rows[0];
    QByteArray encrypted_key = key_row["encrypted_key"].toByteArray();
    QByteArray key_nonce = key_row["nonce"].toByteArray();
    
    // Decrypt the symmetric key using KEK
    auto decrypted_key = decrypt_symmetric_key(
        q_byte_array_to_chars(encrypted_key),
        q_byte_array_to_chars(key_nonce)
    );
    
    // Decrypt the message using the decrypted symmetric key
    auto decrypted_message = decrypt_message_with_nonce(
        encrypted_message,
        decrypted_key,
        std::vector<unsigned char>(message_nonce.begin(), message_nonce.end())
    );
    
    return decrypted_message;
}

// Function to get all messages for a user
inline std::vector<std::tuple<std::string, std::array<unsigned char, 32>, std::vector<unsigned char>>> get_all_decrypted_messages_for_user(const std::string& username) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    
    // Get all messages for the user
    db.prepare_or_throw(
        "SELECT from_device_id, encrypted_message, nonce, file_uuid FROM messages WHERE username = ?;", &stmt
    );
    sqlite3_bind_text(stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
    
    auto rows = db.query(stmt);
    std::vector<std::tuple<std::string, std::array<unsigned char, 32>, std::vector<unsigned char>>> result;
    
    for (const auto& row : rows) {
        QByteArray device_id_bytes = row["from_device_id"].toByteArray();
        QByteArray encrypted_message = row["encrypted_message"].toByteArray();
        QByteArray message_nonce = row["nonce"].toByteArray();
        std::string file_uuid = row["file_uuid"].toString().toStdString();
        
        // Convert device_id to array
        std::array<unsigned char, 32> device_id;
        if (device_id_bytes.size() == 32) {
            std::memcpy(device_id.data(), device_id_bytes.constData(), 32);
        } else {
            continue; // Skip invalid device_id
        }
        
        // Get the corresponding key
        sqlite3_stmt *key_stmt;
        try {
            db.prepare_or_throw(
                "SELECT encrypted_key, nonce FROM message_keys WHERE username = ? AND device_id = ? AND file_uuid = ?;", &key_stmt
            );
            sqlite3_bind_text(key_stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
            sqlite3_bind_blob(key_stmt, 2, device_id.data(), 32, SQLITE_TRANSIENT);
            sqlite3_bind_text(key_stmt, 3, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
            
            auto key_rows = db.query(key_stmt);
            if (key_rows.empty()) {
                continue; // Skip if no key found
            }
            
            const auto &key_row = key_rows[0];
            QByteArray encrypted_key = key_row["encrypted_key"].toByteArray();
            QByteArray key_nonce = key_row["nonce"].toByteArray();
            
            auto decrypted_key = decrypt_symmetric_key(
                q_byte_array_to_chars(encrypted_key),
                q_byte_array_to_chars(key_nonce)
            );
            
            auto decrypted_message = decrypt_message_with_nonce(
                encrypted_message,
                decrypted_key,
                std::vector<unsigned char>(message_nonce.begin(), message_nonce.end())
            );
            
            result.emplace_back(file_uuid, device_id, decrypted_message);
        } catch (const std::exception& e) {
            // Skip this message if decryption fails
            std::cerr << "Failed to decrypt message " << file_uuid << " for user " << username << ": " << e.what() << std::endl;
            continue;
        }
    }
    
    return result;
}

// Function to get all decrypted messages from database (excluding current user's messages)
inline std::vector<std::tuple<std::string, std::string, std::array<unsigned char, 32>, std::vector<unsigned char>>> get_all_decrypted_messages() {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    
    // Get current user's username to exclude their messages
    std::string current_username = SessionTokenManager::instance().getUsername();
    
    // Get all messages except those from the current user
    db.prepare_or_throw(
        "SELECT username, from_device_id, encrypted_message, nonce, file_uuid FROM messages WHERE username != ?;", &stmt
    );
    sqlite3_bind_text(stmt, 1, current_username.c_str(), static_cast<int>(current_username.length()), SQLITE_TRANSIENT);
    
    auto rows = db.query(stmt);
    std::vector<std::tuple<std::string, std::string, std::array<unsigned char, 32>, std::vector<unsigned char>>> result;
    std::set<std::string> seen_file_uuids; // Track unique file UUIDs
    
    for (const auto& row : rows) {
        std::string username = row["username"].toString().toStdString();
        QByteArray device_id_bytes = row["from_device_id"].toByteArray();
        QByteArray encrypted_message = row["encrypted_message"].toByteArray();
        QByteArray message_nonce = row["nonce"].toByteArray();
        std::string file_uuid = row["file_uuid"].toString().toStdString();
        
        // Skip if we've already seen this file_uuid
        if (seen_file_uuids.find(file_uuid) != seen_file_uuids.end()) {
            continue;
        }
        seen_file_uuids.insert(file_uuid);
        
        // Convert device_id to array
        std::array<unsigned char, 32> device_id;
        if (device_id_bytes.size() == 32) {
            std::memcpy(device_id.data(), device_id_bytes.constData(), 32);
        } else {
            continue; // Skip invalid device_id
        }
        
        // Get the corresponding key - create a fresh statement for each query
        sqlite3_stmt *key_stmt;
        try {
            db.prepare_or_throw(
                "SELECT encrypted_key, nonce FROM message_keys WHERE username = ? AND device_id = ? AND file_uuid = ?;", &key_stmt
            );
            sqlite3_bind_text(key_stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
            sqlite3_bind_blob(key_stmt, 2, device_id.data(), 32, SQLITE_TRANSIENT);
            sqlite3_bind_text(key_stmt, 3, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
            
            auto key_rows = db.query(key_stmt);
            if (key_rows.empty()) {
                continue; // Skip if no key found
            }
            
            const auto &key_row = key_rows[0];
            QByteArray encrypted_key = key_row["encrypted_key"].toByteArray();
            QByteArray key_nonce = key_row["nonce"].toByteArray();
            
            auto decrypted_key = decrypt_symmetric_key(
                q_byte_array_to_chars(encrypted_key),
                q_byte_array_to_chars(key_nonce)
            );
            auto decrypted_message = decrypt_message_with_nonce(
                encrypted_message,
                decrypted_key,
                std::vector<unsigned char>(message_nonce.begin(), message_nonce.end())
            );
            
            result.emplace_back(username, file_uuid, device_id, decrypted_message);
        } catch (const std::exception& e) {
            // Skip this message if decryption fails
            std::cerr << "Failed to decrypt message " << file_uuid << " for user " << username << ": " << e.what() << std::endl;
            continue;
        }
    }
    
    return result;
}

inline std::vector<std::tuple<std::string, std::string>> get_all_received_file_uuids() {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;

    // Get current user's username to exclude their messages
    std::string current_username = SessionTokenManager::instance().getUsername();

    // Get all messages except those from the current user
    db.prepare_or_throw(
        "SELECT file_uuid, username FROM messages WHERE username != ? AND is_sender = 0;", &stmt
    );
    sqlite3_bind_text(stmt, 1, current_username.c_str(), static_cast<int>(current_username.length()), SQLITE_TRANSIENT);

    auto rows = db.query(stmt);
    std::set<std::string> seen_file_uuids; // Track unique file UUIDs
    std::vector<std::tuple<std::string, std::string>> file_uuids;

    for (const auto& row : rows) {
        std::string file_uuid = row["file_uuid"].toString().toStdString();
        std::string username = row["username"].toString().toStdString();

        // Skip if we've already seen this file_uuid
        if (seen_file_uuids.find(file_uuid) != seen_file_uuids.end()) {
            continue;
        }
        seen_file_uuids.insert(file_uuid);
        file_uuids.emplace_back(std::make_tuple(file_uuid, username));
    }

    return file_uuids;
}

inline std::vector<std::tuple<std::string,std::string>> get_all_sent_file_uuids() {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;

    std::string current_username = SessionTokenManager::instance().getUsername();

    db.prepare_or_throw(
        "SELECT file_uuid, username FROM messages WHERE username != ? AND is_sender = 1;", &stmt
    );
    sqlite3_bind_text(stmt, 1, current_username.c_str(), static_cast<int>(current_username.length()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, current_username.c_str(), static_cast<int>(current_username.length()), SQLITE_TRANSIENT);

    auto rows = db.query(stmt);
    std::set<std::string> seen_file_uuids; // Track unique file UUIDs
    std::vector<std::tuple<std::string, std::string>> file_uuids;

    for (const auto& row : rows) {
        std::string file_uuid = row["file_uuid"].toString().toStdString();
        std::string username = row["username"].toString().toStdString();

        // Skip if we've already seen this file_uuid
        if (seen_file_uuids.find(file_uuid) != seen_file_uuids.end()) {
            continue;
        }
        seen_file_uuids.insert(file_uuid);
        file_uuids.emplace_back(std::make_tuple(file_uuid, username));
    }

    return file_uuids;
}

// Function to get all ratchets from database
inline std::vector<std::tuple<std::string, std::array<unsigned char, 32>, std::vector<unsigned char>>> get_all_decrypted_ratchets() {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;

    // Get all ratchets
    db.prepare_or_throw(
        "SELECT username, device_id, encrypted_data, nonce FROM ratchets;", &stmt
    );

    auto rows = db.query(stmt);
    std::vector<std::tuple<std::string, std::array<unsigned char, 32>, std::vector<unsigned char>>> result;

    for (const auto& row : rows) {
        std::string username = row["username"].toString().toStdString();
        QByteArray device_id_bytes = row["device_id"].toByteArray();
        QByteArray encrypted_data = row["encrypted_data"].toByteArray();
        QByteArray ratchet_nonce = row["nonce"].toByteArray();

        // Convert device_id to array
        std::array<unsigned char, 32> device_id;
        if (device_id_bytes.size() == 32) {
            std::memcpy(device_id.data(), device_id_bytes.constData(), 32);
        } else {
            continue; // Skip invalid device_id
        }

        // Get the corresponding key - create a fresh statement for each query
        sqlite3_stmt *key_stmt;
        try {
            db.prepare_or_throw(
                "SELECT encrypted_key, nonce FROM ratchet_keys WHERE username = ? AND device_id = ?;", &key_stmt
            );
            sqlite3_bind_text(key_stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
            sqlite3_bind_blob(key_stmt, 2, device_id.data(), 32, SQLITE_TRANSIENT);

            auto key_rows = db.query(key_stmt);
            if (key_rows.empty()) {
                continue; // Skip if no key found
            }

            const auto &key_row = key_rows[0];
            QByteArray encrypted_key = key_row["encrypted_key"].toByteArray();
            QByteArray key_nonce = key_row["nonce"].toByteArray();

            auto decrypted_key = decrypt_symmetric_key(
                q_byte_array_to_chars(encrypted_key),
                q_byte_array_to_chars(key_nonce)
            );

            auto decrypted_ratchet = decrypt_message_with_nonce(
                encrypted_data,
                decrypted_key,
                std::vector<unsigned char>(ratchet_nonce.begin(), ratchet_nonce.end())
            );

            result.emplace_back(username, device_id, decrypted_ratchet);
        } catch (const std::exception& e) {
            // Skip this ratchet if decryption fails
            std::cerr << "Failed to decrypt ratchet for user " << username << ": " << e.what() << std::endl;
            continue;
        }
    }

    return result;
}

// Function to get all sent messages by current user from database
inline std::vector<std::tuple<std::string, std::string, std::array<unsigned char, 32>, std::vector<unsigned char>>> get_all_decrypted_sent_messages() {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    
    // Get current user's username to show only their messages
    std::string current_username = SessionTokenManager::instance().getUsername();
    
    // Get all messages sent by the current user
    db.prepare_or_throw(
        "SELECT username, from_device_id, encrypted_message, nonce, file_uuid FROM messages WHERE username = ?;", &stmt
    );
    sqlite3_bind_text(stmt, 1, current_username.c_str(), static_cast<int>(current_username.length()), SQLITE_TRANSIENT);
    
    auto rows = db.query(stmt);
    std::vector<std::tuple<std::string, std::string, std::array<unsigned char, 32>, std::vector<unsigned char>>> result;
    std::set<std::string> seen_file_uuids; // Track unique file UUIDs
    
    for (const auto& row : rows) {
        std::string username = row["username"].toString().toStdString();
        QByteArray device_id_bytes = row["from_device_id"].toByteArray();
        QByteArray encrypted_message = row["encrypted_message"].toByteArray();
        QByteArray message_nonce = row["nonce"].toByteArray();
        std::string file_uuid = row["file_uuid"].toString().toStdString();
        
        // Skip if we've already seen this file_uuid
        if (seen_file_uuids.find(file_uuid) != seen_file_uuids.end()) {
            continue;
        }
        seen_file_uuids.insert(file_uuid);
        
        // Convert device_id to array
        std::array<unsigned char, 32> device_id;
        if (device_id_bytes.size() == 32) {
            std::memcpy(device_id.data(), device_id_bytes.constData(), 32);
        } else {
            continue; // Skip invalid device_id
        }
        
        // Get the corresponding key - create a fresh statement for each query
        sqlite3_stmt *key_stmt;
        try {
            db.prepare_or_throw(
                "SELECT encrypted_key, nonce FROM message_keys WHERE username = ? AND device_id = ? AND file_uuid = ?;", &key_stmt
            );
            sqlite3_bind_text(key_stmt, 1, username.c_str(), static_cast<int>(username.length()), SQLITE_TRANSIENT);
            sqlite3_bind_blob(key_stmt, 2, device_id.data(), 32, SQLITE_TRANSIENT);
            sqlite3_bind_text(key_stmt, 3, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
            
            auto key_rows = db.query(key_stmt);
            if (key_rows.empty()) {
                continue; // Skip if no key found
            }
            
            const auto &key_row = key_rows[0];
            QByteArray encrypted_key = key_row["encrypted_key"].toByteArray();
            QByteArray key_nonce = key_row["nonce"].toByteArray();
            
            auto decrypted_key = decrypt_symmetric_key(
                q_byte_array_to_chars(encrypted_key),
                q_byte_array_to_chars(key_nonce)
            );
            auto decrypted_message = decrypt_message_with_nonce(
                encrypted_message,
                decrypted_key,
                std::vector<unsigned char>(message_nonce.begin(), message_nonce.end())
            );
            
            result.emplace_back(username, file_uuid, device_id, decrypted_message);
        } catch (const std::exception& e) {
            // Skip this message if decryption fails
            std::cerr << "Failed to decrypt sent message " << file_uuid << " for user " << username << ": " << e.what() << std::endl;
            continue;
        }
    }
    
    return result;
}

inline std::vector<std::string> get_file_recipients(const std::string& file_uuid) {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    
    std::cout << "DEBUG: Getting recipients for file UUID: " << file_uuid << std::endl;
    
    // Get current user's username to exclude them
    std::string current_username = SessionTokenManager::instance().getUsername();
    std::cout << "DEBUG: Current user: " << current_username << std::endl;
    
    // Get all unique usernames who have received this file, excluding current user
    db.prepare_or_throw(
        "SELECT DISTINCT username FROM messages WHERE file_uuid = ? AND username != ? AND is_sender = 1;", &stmt
    );
    sqlite3_bind_text(stmt, 1, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, current_username.c_str(), static_cast<int>(current_username.length()), SQLITE_TRANSIENT);
    
    auto rows = db.query(stmt);
    std::vector<std::string> recipients;
    
    for (const auto& row : rows) {
        std::string username = row["username"].toString().toStdString();
        recipients.push_back(username);
        std::cout << "DEBUG: Found recipient: " << username << std::endl;
    }
    
    std::cout << "DEBUG: Total recipients for file " << file_uuid << " (excluding current user): " << recipients.size() << std::endl;
    return recipients;
}

inline void delete_file_from_database(const std::string& file_uuid) {
    const auto &db = Database::get();
    
    std::cout << "DEBUG: Deleting file " << file_uuid << " from database" << std::endl;
    
    try {
        sqlite3_stmt *stmt1;
        db.prepare_or_throw("DELETE FROM file_keys WHERE file_uuid = ?;", &stmt1);
        sqlite3_bind_text(stmt1, 1, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
        db.execute(stmt1);
        std::cout << "DEBUG: Deleted from file_keys table" << std::endl;
        
        sqlite3_stmt *stmt2;
        db.prepare_or_throw("DELETE FROM messages WHERE file_uuid = ?;", &stmt2);
        sqlite3_bind_text(stmt2, 1, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
        db.execute(stmt2);
        std::cout << "DEBUG: Deleted from messages table" << std::endl;
        
        sqlite3_stmt *stmt3;
        db.prepare_or_throw("DELETE FROM message_keys WHERE file_uuid = ?;", &stmt3);
        sqlite3_bind_text(stmt3, 1, file_uuid.c_str(), static_cast<int>(file_uuid.length()), SQLITE_TRANSIENT);
        db.execute(stmt3);
        std::cout << "DEBUG: Deleted from message_keys table" << std::endl;
        
        std::cout << "DEBUG: Successfully deleted file " << file_uuid << " from all database tables" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "ERROR: Failed to delete file " << file_uuid << " from database: " << e.what() << std::endl;
        throw;
    }
}

inline QDateTime get_signed_prekey_last_updated() {
    const auto &db = Database::get();
    sqlite3_stmt *stmt;
    db.prepare_or_throw("SELECT last_modified FROM keypairs WHERE label = 'signed'", &stmt);
    auto rows = db.query(stmt);
    if (rows.empty()) {
        return QDateTime();
    }
    const auto &row = rows[0];
    return row["last_modified"].toDateTime();
}

#endif //QUERIES_H
