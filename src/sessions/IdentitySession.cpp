//
// Created by Josh Sloggett on 28/05/2025.
//

#include "IdentitySession.h"

#include "src/endpoints/endpoints.h"
#include "src/key_exchange/utils.h"

IdentitySession::IdentitySession(std::vector<KeyBundle*> const &keys, unsigned char* identity_one, unsigned char* identity_two) {
    size_t out_len;
    unsigned char *concatenated = concat_ordered(identity_one, crypto_box_PUBLICKEYBYTES,
                                               identity_two, crypto_box_PUBLICKEYBYTES,
                                               out_len);
    identity_session_id = new unsigned char[crypto_box_PUBLICKEYBYTES * 2];
    memcpy(identity_session_id, concatenated, out_len);
    delete[] concatenated;
    updateFromBundles(keys);
}

void IdentitySession::updateFromBundles(std::vector<KeyBundle*> bundles) {
    for (KeyBundle* bundle: bundles) {
        unsigned char* my_dev_pub = bundle->get_my_device_public();
        unsigned char* their_dev_pub = bundle->get_their_device_public();
        
        create_ratchet_if_needed(my_dev_pub, their_dev_pub, bundle);
    }
}

void IdentitySession::create_ratchet_if_needed(const unsigned char* device_id_one, const unsigned char* device_id_two, KeyBundle* bundle) {
    size_t out_len;
    unsigned char* concatenated = concat_ordered(device_id_one, crypto_box_PUBLICKEYBYTES,
                                               device_id_two, crypto_box_PUBLICKEYBYTES,
                                               out_len);
    
    // Check if a ratchet exists for this key
    bool exists = ratchets.find(concatenated) != ratchets.end();
    
    if (!exists) {
        // Create new DoubleRatchet instance with the bundle
        auto ratchet = std::make_unique<DoubleRatchet>(bundle);
        ratchets[concatenated] = std::move(ratchet);

        if (bundle->get_role() == Role::Initiator) {
            auto sender = dynamic_cast<SendingKeyBundle*>(bundle);
            post_handshake_device(identity_session_id, sender->get_their_device_public(), sender->get_their_signed_public(), sender->get_their_signed_signature(), sender->get_their_onetime_public(), sender->get_my_device_public(), sender->get_my_ephemeral_public());
        };
    }
    
    delete[] concatenated;
}

