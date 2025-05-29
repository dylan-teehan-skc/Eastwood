//
// Created by Josh Sloggett on 28/05/2025.
//

#include "IdentityManager.h"
#include <iostream>
#include <cstring>

#include "src/key_exchange/utils.h"

void IdentityManager::update_or_create_identity_sessions(std::vector<KeyBundle*> bundles, unsigned char* identity_one, unsigned char* identity_two) {
    // Create a key by concatenating the two identity keys in lexicographical order
    unsigned char* concatenated = new unsigned char[crypto_box_PUBLICKEYBYTES * 2];
    if (memcmp(identity_one, identity_two, crypto_box_PUBLICKEYBYTES) < 0) {
        memcpy(concatenated, identity_one, crypto_box_PUBLICKEYBYTES);
        memcpy(concatenated + crypto_box_PUBLICKEYBYTES, identity_two, crypto_box_PUBLICKEYBYTES);
    } else {
        memcpy(concatenated, identity_two, crypto_box_PUBLICKEYBYTES);
        memcpy(concatenated + crypto_box_PUBLICKEYBYTES, identity_one, crypto_box_PUBLICKEYBYTES);
    }

    // Check if a session already exists for this identity pair
    if (_sessions.find(concatenated) == _sessions.end()) {
        std::cout << "Session creating... (identity manager)" << std::endl;
        // Create a new session with the bundles
        auto session = std::make_unique<IdentitySession>(bundles, identity_one, identity_two);
        _sessions[concatenated] = std::move(session);
    } else {
        // Update existing session with new bundles
        _sessions[concatenated]->updateFromBundles(bundles);
    }

    // Clean up
    delete[] concatenated;
}

