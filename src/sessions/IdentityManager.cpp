//
// Created by Josh Sloggett on 28/05/2025.
//

#include "IdentityManager.h"
#include <iostream>
#include <cstring>

#include "src/endpoints/endpoints.h"
#include "src/keys/session_token_manager.h"
#include "src/key_exchange/utils.h"

void IdentityManager::update_or_create_identity_sessions(std::vector<KeyBundle*> bundles, std::string username_one, std::string username_two) {
    // Create a key by concatenating the two identity keys in lexicographical order
    unsigned char* session_id_raw = generate_unique_id_pair(&username_one, &username_two);
    IdentitySessionId session_id;
    memcpy(session_id.data.data(), session_id_raw, crypto_hash_sha256_BYTES);
    delete[] session_id_raw;

    // Check if a session already exists for this identity pair
    if (_sessions.find(session_id) == _sessions.end()) {
        std::cout << "Session creating... (identity manager)" << std::endl;
        // Create a new session with the bundles
        auto session = std::make_unique<IdentitySession>(bundles, session_id.data.data());
        _sessions[session_id] = std::move(session);
    } else {
        // Update existing session with new bundles
        _sessions[session_id]->updateFromBundles(bundles);
    }
}

void IdentityManager::update_or_create_identity_sessions(std::vector<std::tuple<IdentitySessionId, KeyBundle*>> bundles_with_ids) {
    // Group bundles by their identity session ID
    std::map<IdentitySessionId, std::vector<KeyBundle*>> bundles_by_id;
    
    // First pass: group bundles by their identity session ID
    for (const auto& [id, bundle] : bundles_with_ids) {
        bundles_by_id[id].push_back(bundle);
    }
    
    // Second pass: create or update sessions for each ID
    for (const auto& [id, bundles] : bundles_by_id) {
        std::cout << "checking id" << bin2hex(id.data.data(), crypto_hash_sha256_BYTES) << std::endl;
        if (_sessions.find(id) == _sessions.end()) {
            std::cout << "Session creating... (identity manager)" << std::endl;
            // Create a new session with the bundles
            auto session = std::make_unique<IdentitySession>(bundles, id.data.data());
            _sessions[id] = std::move(session);
        } else {
            // Update existing session with new bundles
            _sessions[id]->updateFromBundles(bundles);
        }
    }
}

std::vector<std::tuple<IdentitySessionId, std::unique_ptr<DeviceMessage>>> IdentityManager::send_to_user(std::string username, unsigned char *msg) {
    std::string my_username = SessionTokenManager::instance().getUsername();
    unsigned char* session_id_raw = generate_unique_id_pair(&username, &my_username);
    IdentitySessionId session_id;
    memcpy(session_id.data.data(), session_id_raw, crypto_hash_sha256_BYTES);
    delete[] session_id_raw;

    // Check if session exists
    if (_sessions.find(session_id) == _sessions.end()) {
        std::cout << "No session found for identity: ";
        for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++) {
            printf("%02x", session_id.data[i]);
        }
        std::cout << "Doing keybundle handshake due to lack of session" << std::endl;
        get_keybundles(username);
    }

    std::vector<std::tuple<IdentitySessionId, std::unique_ptr<DeviceMessage>>> msgs = _sessions[session_id]->send_message(msg, sizeof(msg));
    return msgs;
}

void IdentityManager::receive_messages(std::vector<std::tuple<IdentitySessionId, DeviceMessage*>> messages_with_ids) {
    // Group messages by their identity session ID
    std::map<IdentitySessionId, std::vector<DeviceMessage*>> messages_by_id;

    // First pass: group messages by their identity session ID
    for (const auto& [id, message] : messages_with_ids) {
        messages_by_id[id].push_back(message);
    }

    // Second pass: route messages to their respective sessions
    for (const auto& [id, messages] : messages_by_id) {
        if (_sessions.find(id) == _sessions.end()) {
            std::cout << "No session found for identity: ";
            for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++) {
                printf("%02x", id.data[i]);
            }
            std::cout << std::endl;
            continue;
        }
        
        // Route each message to the session
        for (auto* message : messages) {
            _sessions[id]->receive_message(message);
            delete message; // Clean up the message after processing
        }
    }

}

void IdentityManager::print_all_session_ids() {
    std::cout << "\n=== Current Identity Sessions ===" << std::endl;
    if (_sessions.empty()) {
        std::cout << "No active sessions" << std::endl;
        return;
    }
    
    int count = 1;
    for (const auto& [id, session] : _sessions) {
        std::cout << "Session " << count++ << ": ";
        for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++) {
            printf("%02x", id.data[i]);
        }
        std::cout << std::endl;
    }
    std::cout << "==============================\n" << std::endl;
}




