//
// Created by Josh Sloggett on 01/06/2025.
//

#include "RatchetSessionManager.h"
#include <iostream>

#include "src/endpoints/endpoints.h"
#include "src/utils/JsonParser.h"

// Singleton instance method
RatchetSessionManager& RatchetSessionManager::instance() {
    static RatchetSessionManager instance;
    return instance;
}

RatchetSessionManager::RatchetSessionManager() = default;

RatchetSessionManager::~RatchetSessionManager() {
    ratchets.clear();
}

void RatchetSessionManager::create_ratchets_if_needed(const std::string &username, const std::vector<KeyBundle*> &bundles, const bool post_to_server) {
    auto& user_ratchets = ratchets[username];

    for (KeyBundle* bundle : bundles) {
        std::array<unsigned char, 32> device_id{};
        std::memcpy(device_id.data(), bundle->get_their_device_public(), 32);

        if (user_ratchets.find(device_id) == user_ratchets.end()) {
            std::cout << "creating ratchet for " << username << std::endl;
            user_ratchets[device_id] = bundle->create_ratchet();
            // Save the newly created ratchet
            user_ratchets[device_id]->save(username, device_id);

            auto sending_bundle = dynamic_cast<SendingKeyBundle*>(bundle);

            if (post_to_server && sending_bundle) {
                try {
                    post_handshake_device(
                        sending_bundle->get_their_device_public(),
                        sending_bundle->get_their_signed_public(),
                        sending_bundle->get_their_signed_signature(),
                        sending_bundle->get_their_onetime_public(),
                        sending_bundle->get_my_ephemeral_public()
                    );
                    std::cout << "Successfully posted handshake to server for " << username << std::endl;
                } catch (const webwood::HttpError& e) {
                    std::cerr << "Server error when posting handshake for " << username << ": " << e.what() << std::endl;
                    // Continue execution - ratchet is still created locally
                } catch (const std::exception& e) {
                    std::cerr << "Error posting handshake for " << username << ": " << e.what() << std::endl;
                    // Continue execution - ratchet is still created locally
                }
            }
        }
    }
    
    // Note: Not deleting KeyBundle objects here as they may be reused
    // Caller is responsible for cleanup
}


std::map<std::array<unsigned char, 32>, std::tuple<std::array<unsigned char, 32>, MessageHeader *> > RatchetSessionManager::get_keys_for_identity(const std::string &username, bool post_new_ratchets_to_server) {
    if (post_new_ratchets_to_server) {
        const auto new_bundles = get_keybundles(username, get_device_ids_of_existing_handshakes(username));
        create_ratchets_if_needed(username, new_bundles, post_new_ratchets_to_server);
        
        for (auto* bundle : new_bundles) {
            delete bundle;
        }
    }

    std::map<std::array<unsigned char, 32>, std::tuple<std::array<unsigned char, 32>, MessageHeader *> > keys;
    auto& ratchets_for_user = ratchets[username];

    // Get my (sender's) device public key from database
    auto my_device_public = get_public_key("device");

    for (auto& [device_id, ratchet] : ratchets_for_user) {
        auto [message_key_vector, header] = ratchet->advance_send();
        ratchet->save(username, device_id);
        
        memcpy(header->device_id.data(), my_device_public.data(), 32);
        
        std::array<unsigned char, 32> message_key_array{};
        std::copy_n(message_key_vector.begin(), 32, message_key_array.begin());
        
        keys[device_id] = std::make_tuple(message_key_array, header);
    }

    return keys;
}


unsigned char* RatchetSessionManager::get_key_for_device(const std::string &username, MessageHeader* header) {
    std::array<unsigned char, 32> device_id{};
    std::copy(header->device_id.begin(), header->device_id.end(), device_id.begin());
    
    auto user_it = ratchets.find(username);
    if (user_it == ratchets.end()) {
        throw std::runtime_error("User not found: " + username);
    }
    
    auto target_ratchet = user_it->second.find(device_id);
    if (target_ratchet == user_it->second.end()) {
        throw std::runtime_error("Device not found for user: " + username);
    }
    
    auto result = target_ratchet->second->advance_receive(header);
    
    target_ratchet->second->save(username, device_id);
    
    return result;
}

void RatchetSessionManager::load_ratchets_from_db() {
    try {
        auto all_ratchets = get_all_decrypted_ratchets();
        
        for (const auto& [username, device_id, serialized_ratchet] : all_ratchets) {
            try {
                // Create NewRatchet from serialized data
                auto ratchet = std::make_unique<NewRatchet>(serialized_ratchet);
                
                // Add to the ratchets map
                ratchets[username][device_id] = std::move(ratchet);
            } catch (const std::exception& e) {
                std::cerr << "Failed to deserialize ratchet for user " << username << ": " << e.what() << std::endl;
                continue;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to load ratchets from database: " << e.what() << std::endl;
        throw;
    }
}

std::vector<std::array<unsigned char,32> > RatchetSessionManager::get_device_ids_of_existing_handshakes(const std::string &username) {
    std::vector<std::array<unsigned char,32> > device_ids;

    auto user_it = ratchets.find(username);
    if (user_it == ratchets.end()) {
        return device_ids;
    }

    for (const auto& [device_id, ratchet] : user_it->second) {
        device_ids.push_back(device_id);
    }
    return device_ids;
}

