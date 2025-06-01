//
// Created by Josh Sloggett on 01/06/2025.
//

#include "RatchetSessionManager.h"
#include <iostream>

RatchetSessionManager::RatchetSessionManager() {
    // No need to initialize ratchets as it's already default-initialized
}

void RatchetSessionManager::create_ratchets_if_needed(std::string username, std::vector<KeyBundle*> bundles) {
    auto& user_ratchets = ratchets[username];

    for (KeyBundle* bundle : bundles) {
        std::array<unsigned char, 32> device_id;
        std::memcpy(device_id.data(), bundle->get_their_device_public(), 32);

        if (user_ratchets.find(device_id) == user_ratchets.end()) {
            std::cout << "creating ratchet for " << username << std::endl;
            user_ratchets[device_id] = bundle->create_ratchet();
            // Save the newly created ratchet
            user_ratchets[device_id]->save(username, device_id);
        }
    }
}


std::map<std::array<unsigned char, 32>, std::tuple<std::array<unsigned char, 32>, MessageHeader *> > RatchetSessionManager::get_keys_for_identity(std::string username) {
    std::map<std::array<unsigned char, 32>, std::tuple<std::array<unsigned char, 32>, MessageHeader *> > keys;
    auto& ratchets_for_user = ratchets[username];

    // Get my (sender's) device public key from database
    auto my_device_public = get_public_key("device");

    for (auto& [device_id, ratchet] : ratchets_for_user) {
        auto [message_key_vector, header] = ratchet->advance_send();
        
        // Save the ratchet state after advancing send
        ratchet->save(username, device_id);
        
        // Set the header device_id to the sender's (my) device ID so receiver can look up correct ratchet
        memcpy(header->device_id, my_device_public.constData(), 32);
        
        // Convert vector to array
        std::array<unsigned char, 32> message_key_array;
        std::copy(message_key_vector.begin(), message_key_vector.begin() + 32, message_key_array.begin());
        
        keys[device_id] = std::make_tuple(message_key_array, header);
    }

    return keys;
}


unsigned char* RatchetSessionManager::get_key_for_device(std::string username, MessageHeader* header) {
    std::array<unsigned char, 32> device_id;
    std::copy(std::begin(header->device_id), std::end(header->device_id), device_id.begin());
    
    auto user_it = ratchets.find(username);
    if (user_it == ratchets.end()) {
        throw std::runtime_error("User not found: " + username);
    }
    
    std::cout << "Looking for ratchets under username: " << username << std::endl;
    std::cout << "Available ratchets for " << username << ":" << std::endl;
    for (const auto& [stored_device_id, ratchet] : user_it->second) {
        std::cout << "  Device ID: ";
        for (int i = 0; i < 32; i++) {
            printf("%02x", stored_device_id[i]);
        }
        std::cout << std::endl;
    }
    
    std::cout << "Looking for device ID from header: ";
    for (int i = 0; i < 32; i++) {
        printf("%02x", header->device_id[i]);
    }
    std::cout << std::endl;
    
    auto target_ratchet = user_it->second.find(device_id);
    if (target_ratchet == user_it->second.end()) {
        throw std::runtime_error("Device not found for user: " + username);
    }
    
    auto result = target_ratchet->second->advance_receive(header);
    
    // Save the ratchet state after advancing receive
    target_ratchet->second->save(username, device_id);
    
    return result;
}

