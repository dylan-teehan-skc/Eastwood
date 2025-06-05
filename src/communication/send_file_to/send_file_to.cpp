//
// Created by Fred Sheppard on 04/06/2025.
//

#include "send_file_to.h"

#include <map>
#include <string>

#include "src/algorithms/constants.h"
#include "src/communication/upload_file/upload_file.h"
#include "src/endpoints/endpoints.h"
#include "src/keys/secure_memory_buffer.h"
#include "src/keys/session_token_manager.h"
#include "src/key_exchange/MessageStructs.h"
#include "src/algorithms/algorithms.h"
#include "src/sessions/RatchetSessionManager.h"

void allow_access_to_file(
    const std::string &username,
    const std::string &uuid,
    const std::unique_ptr<SecureMemoryBuffer> &f_kek,
    bool get_keybundles
) {
    const auto file_key = SecureMemoryBuffer::create(SYM_KEY_LEN);
    randombytes_buf(file_key->data(), SYM_KEY_LEN);

    std::map<std::array<unsigned char, 32>, std::tuple<std::array<unsigned char, 32>, MessageHeader> > keys_to_send_key
            = RatchetSessionManager::instance().get_keys_for_identity(username, get_keybundles);

    if (keys_to_send_key.size() > 0) {
        std::vector<std::tuple<std::array<unsigned char, 32>, DeviceMessage *> > messages;
        for (const auto &[device_id, ratchet_key_message_header_pair]: keys_to_send_key) {
            const auto &[key, message_header] = ratchet_key_message_header_pair;

            auto message = new DeviceMessage();
            message->header = message_header;
            strncpy(message->header.file_uuid, uuid.c_str(), sizeof(message->header.file_uuid) - 1);
            message->header.file_uuid[sizeof(message->header.file_uuid) - 1] = '\0';

            // Encrypt the file key using the message key
            message->ciphertext = encrypt_message_given_key(f_kek->data(), f_kek->size(), key.data());

            messages.push_back(std::make_tuple(device_id, message));
        }
        post_ratchet_message(messages, SessionTokenManager::instance().getUsername());

        // Save sent messages to database (similar to received_dash.cpp)
        for (auto [device_id, msg]: messages) {
            // Get the file key that was encrypted in the message
            // Re-encrypt the file key with a new symmetric key for database storage
            auto message_encryption_key = SecureMemoryBuffer::create(32);
            crypto_aead_chacha20poly1305_ietf_keygen(message_encryption_key->data());

            // Generate nonce for message encryption
            unsigned char message_nonce[CHA_CHA_NONCE_LEN];
            randombytes_buf(message_nonce, CHA_CHA_NONCE_LEN);

            // Copy the encryption key for saving BEFORE moving it
            auto sk_buffer = SecureMemoryBuffer::create(32);
            memcpy(sk_buffer->data(), message_encryption_key->data(), 32);

            // Encrypt the file key (which was the original "message" content)
            auto encrypted_message_again = encrypt_message_with_nonce(
                QByteArray(reinterpret_cast<const char *>(f_kek->data()), f_kek->size()),
                std::move(message_encryption_key),
                message_nonce
            );

            unsigned char key_nonce [CHA_CHA_NONCE_LEN];
            randombytes_buf(key_nonce, CHA_CHA_NONCE_LEN);

            auto encrypted_key = encrypt_symmetric_key(sk_buffer, key_nonce);

            // Extract file_uuid from header
            std::string file_uuid(msg->header.file_uuid);

            // Save using current user as sender (since this is a sent message)
            save_message_and_key(username, device_id, file_uuid, encrypted_message_again, message_nonce,
                                 encrypted_key, key_nonce, true);
        }

        // Clean up DeviceMessage objects after posting
        for (auto [device_id, msg]: messages) {
            delete msg; // DeviceMessage destructor handles header and ciphertext cleanup
        }
    }
}

void send_file_to(const std::string &username, const std::string &file_path, bool get_keybundles) {
    const auto f_kek = SecureMemoryBuffer::create(SYM_KEY_LEN);
    randombytes_buf(f_kek->data(), f_kek->size());

    const std::string uuid = upload_file(file_path, f_kek);
    allow_access_to_file(username, uuid, f_kek, get_keybundles);
}
