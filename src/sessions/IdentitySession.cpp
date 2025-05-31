//
// Created by Josh Sloggett on 28/05/2025.
//

#include "IdentitySession.h"

#include "src/endpoints/endpoints.h"
#include "src/key_exchange/utils.h"
#include "src/key_exchange/XChaCha20-Poly1305.h"

IdentitySession::IdentitySession(std::vector<KeyBundle*> const &keys, const unsigned char* identity_session_id_in) {
    std::cout << "IdentitySession::IdentitySession" << std::endl;
    memcpy(identity_session_id, identity_session_id_in, crypto_hash_sha256_BYTES);
    updateFromBundles(keys);
}

IdentitySession::~IdentitySession() {
    // Clean up any remaining resources
}

void IdentitySession::updateFromBundles(std::vector<KeyBundle*> bundles) {
    std::cout << "IdentitySession::updateFromBundles" << std::endl;
    std::cout << bundles.size() << std::endl;
    for (KeyBundle* bundle: bundles) {
        std::cout << "IdentitySession::updateFromBundles in loop" << std::endl;
        unsigned char* my_dev_pub = bundle->get_my_device_public();
        unsigned char* their_dev_pub = bundle->get_their_device_public();
        
        create_ratchet_if_needed(my_dev_pub, their_dev_pub, bundle);
    }
}

void IdentitySession::create_ratchet_if_needed(const unsigned char* device_id_one, const unsigned char* device_id_two, KeyBundle* bundle) {
    size_t message_len = 32;
    auto ratchet_id = concat_ordered(device_id_one, 32, device_id_two, 32, message_len);

    bool exists = ratchets.find(ratchet_id) != ratchets.end();
    std::cout << "Ratchets exists: " << exists << std::endl;
    
    if (!exists) {
        // Create new DoubleRatchet instance with the bundle
        std::cout << "Creating ratchet" << std::endl;
        auto ratchet = std::make_unique<NewRatchet>(bundle->create_ratchet());
        ratchets[ratchet_id] = std::move(ratchet);

        if (bundle->get_role() == Role::Initiator) {
            auto sender = dynamic_cast<SendingKeyBundle*>(bundle);
            IdentitySessionId session_id;
            memcpy(session_id.data.data(), identity_session_id, crypto_hash_sha256_BYTES);
            post_handshake_device(session_id, sender->get_their_device_public(), sender->get_their_signed_public(), sender->get_their_signed_signature(), sender->get_their_onetime_public(), sender->get_my_device_public(), sender->get_my_ephemeral_public());
        }
    }
}

std::vector<std::tuple<IdentitySessionId, std::unique_ptr<DeviceMessage>>> IdentitySession::send_message(const unsigned char* message, size_t message_len) {
    std::vector<std::tuple<IdentitySessionId, std::unique_ptr<DeviceMessage>>> responses;
    IdentitySessionId session_id{};
    memcpy(session_id.data.data(), identity_session_id, crypto_hash_sha256_BYTES);

    for (const auto& [id, ratchet]: ratchets) {
        auto [key, message_header] = ratchet->advance_send();
        
        // create header
        std::unique_ptr<MessageHeader> header(message_header);

        // encrypt
        auto encrypted = encrypt_message_given_key(message, message_len, key);
        
        // Create DeviceMessage
        auto device_message = std::make_unique<DeviceMessage>();
        device_message->header = header.release();  // Transfer ownership
        device_message->ciphertext = new unsigned char[encrypted.size()];
        device_message->length = encrypted.size();
        memcpy(device_message->ciphertext, encrypted.data(), encrypted.size());

        // add to responses
        responses.emplace_back(session_id, std::move(device_message));
    }
    return responses;
}

std::vector<unsigned char> IdentitySession::receive_message(DeviceMessage *message) {
    size_t message_len = 32;
    auto ratchet_id = concat_ordered(reinterpret_cast<const unsigned char *>(get_public_key("device").data()), 32, message->header->device_id, 32, message_len);

    auto key = ratchets[ratchet_id].get()->advance_receive(message->header);

    std::vector<unsigned char> plaintext = decrypt_message_given_key(message->ciphertext, message->length, key);
    return plaintext;
}


