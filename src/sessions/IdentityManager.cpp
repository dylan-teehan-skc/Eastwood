//
// Created by Josh Sloggett on 28/05/2025.
//

#include "IdentityManager.h"
#include <iostream>
#include <cstring>

#include "src/key_exchange/utils.h"

void IdentityManager::update_or_create_identity_sessions(std::vector<KeyBundle*> bundles, std::string username_one, std::string username_two) {
    // Create a key by concatenating the two identity keys in lexicographical order
    unsigned char* session_id = generate_unique_id_pair(&username_one, &username_two);

    // Check if a session already exists for this identity pair
    if (_sessions.find(session_id) == _sessions.end()) {
        std::cout << "Session creating... (identity manager)" << std::endl;
        // Create a new session with the bundles
        auto session = std::make_unique<IdentitySession>(bundles, session_id);
        _sessions[session_id] = std::move(session);
    } else {
        // Update existing session with new bundles
        _sessions[session_id]->updateFromBundles(bundles);
    }

    // Clean up
    delete[] session_id;
}

void IdentityManager::update_or_create_identity_sessions(std::vector<KeyBundle*> bundles, unsigned char* identity_session_id) {

    // Check if a session already exists for this identity pair
    if (_sessions.find(identity_session_id) == _sessions.end()) {
        std::cout << "Session creating... (identity manager)" << std::endl;
        // Create a new session with the bundles
        auto session = std::make_unique<IdentitySession>(bundles, identity_session_id);
        _sessions[identity_session_id] = std::move(session);
    } else {
        // Update existing session with new bundles
        _sessions[identity_session_id]->updateFromBundles(bundles);
    };
}


