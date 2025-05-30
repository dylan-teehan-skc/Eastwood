//
// Created by Josh Sloggett on 28/05/2025.
//

#include "IdentitySession.h"

#include "src/endpoints/endpoints.h"
#include "src/key_exchange/utils.h"

IdentitySession::IdentitySession(std::vector<KeyBundle*> const &keys, const unsigned char* identity_session_id_in) {
    std::cout << "IdentitySession::IdentitySession" << std::endl;
    memcpy(identity_session_id.data(), identity_session_id_in, crypto_hash_sha256_BYTES);
    std::cout << bin2hex(identity_session_id.data(), crypto_hash_sha256_BYTES) << std::endl;
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
    std::cout << "IdentitySession::create_ratchet_if_needed" << std::endl;
    std::array<unsigned char, crypto_box_PUBLICKEYBYTES * 2> concatenated;
    
    if (memcmp(device_id_one, device_id_two, crypto_box_PUBLICKEYBYTES) <= 0) {
        memcpy(concatenated.data(), device_id_one, crypto_box_PUBLICKEYBYTES);
        memcpy(concatenated.data() + crypto_box_PUBLICKEYBYTES, device_id_two, crypto_box_PUBLICKEYBYTES);
    } else {
        memcpy(concatenated.data(), device_id_two, crypto_box_PUBLICKEYBYTES);
        memcpy(concatenated.data() + crypto_box_PUBLICKEYBYTES, device_id_one, crypto_box_PUBLICKEYBYTES);
    }
    
    // Check if a ratchet exists for this key
    bool exists = ratchets.find(concatenated) != ratchets.end();
    std::cout << "Ratchets exists: " << exists << std::endl;
    
    if (!exists) {
        // Create new DoubleRatchet instance with the bundle
        std::cout << "Creating ratchet" << std::endl;
        auto ratchet = std::make_unique<DoubleRatchet>(bundle);
        ratchets[concatenated] = std::move(ratchet);

        if (bundle->get_role() == Role::Initiator) {
            auto sender = dynamic_cast<SendingKeyBundle*>(bundle);
            IdentitySessionId session_id;
            memcpy(session_id.data.data(), identity_session_id.data(), crypto_hash_sha256_BYTES);
            post_handshake_device(session_id, sender->get_their_device_public(), sender->get_their_signed_public(), sender->get_their_signed_signature(), sender->get_their_onetime_public(), sender->get_my_device_public(), sender->get_my_ephemeral_public());
        }
    }
}

void IdentitySession::send_message(unsigned char *message) {
    for (const auto& [id, ratchet]: ratchets) {
        ratchet.get()->message_send(message, identity_session_id.data());
    }
}

void IdentitySession::receive_message(DeviceMessage *message) {
    for (const auto& [id, ratchet]: ratchets) {
        ratchet.get()->message_receive(*message);
    }
}


