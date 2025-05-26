#include "DoubleRatchet.h"
#include "utils.h"
#include <cstring>
#include <sodium.h>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "XChaCha20-Poly1305.h"

// Context strings for key derivation - must be exactly 8 bytes
const char* const ROOT_CTX = "DRROOT01";
const char* const CHAIN_CTX = "DRCHAIN1";
const char* const MSG_CTX = "DRMSG001";

DoubleRatchet::DoubleRatchet(const unsigned char* x3dh_root_key,
              const unsigned char* remote_public_signed_prekey,
              const unsigned char* local_public_ephemeral,
              const unsigned char* local_private_ephemeral) {

    send_chain.index = 0;
    recv_chain.index = 0;
    prev_send_chain_length = 0;

    // Initialize keys
    memset(send_chain.chain_key, 0, crypto_kdf_KEYBYTES);
    memset(recv_chain.chain_key, 0, crypto_kdf_KEYBYTES);
    
    // Use vectors for all binary fields
    local_dh_public.resize(crypto_box_PUBLICKEYBYTES);
    local_dh_private.resize(crypto_box_PUBLICKEYBYTES);
    root_key.resize(crypto_box_PUBLICKEYBYTES);
    remote_dh_public.resize(crypto_box_PUBLICKEYBYTES);
    
    memcpy(local_dh_public.data(), local_public_ephemeral, crypto_box_PUBLICKEYBYTES);
    memcpy(local_dh_private.data(), local_private_ephemeral, crypto_box_PUBLICKEYBYTES);
    memcpy(root_key.data(), x3dh_root_key, crypto_box_PUBLICKEYBYTES);
    memcpy(remote_dh_public.data(), remote_public_signed_prekey, crypto_box_PUBLICKEYBYTES);
    
    std::cout << "DoubleRatchet initialized with root key: ";
    for (unsigned char i : root_key)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
    std::cout << std::endl;
}

DoubleRatchet::DoubleRatchet()
    : root_key(), local_dh_public(), local_dh_private(), remote_dh_public(),
      send_chain{}, recv_chain{}, prev_send_chain_length(0), skipped_message_keys() {
    // All members are default-initialized (empty vectors, zeroed chains, etc.)
}

DoubleRatchet::~DoubleRatchet() {
    // No manual cleanup needed - vectors and smart pointers handle it
}

void DoubleRatchet::dh_ratchet(const unsigned char* remote_public_key, bool is_sending) {
    if (is_sending) {
        // When sending, generate a new DH keypair
        crypto_kx_keypair(local_dh_public.data(), local_dh_private.data());
    } else if (remote_public_key) {
        // When receiving, store the length of the current sending chain
        prev_send_chain_length = send_chain.index;
        
        // Update remote public key with the one from the message
        memcpy(remote_dh_public.data(), remote_public_key, crypto_kx_PUBLICKEYBYTES);
        
        // Reset sending chain index when we start a new one
        send_chain.index = 0;
    }
    
    // Compute shared secret using DH
    unsigned char shared_secret[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared_secret, local_dh_private.data(), remote_dh_public.data()) != 0) {
        throw std::runtime_error("Error in crypto_scalarmult");
    }
    
    // Derive new keys from the shared secret
    kdf_ratchet(shared_secret, is_sending ? send_chain.chain_key : recv_chain.chain_key, is_sending);
}

void DoubleRatchet::kdf_ratchet(const unsigned char* shared_secret, unsigned char* chain_key, bool is_sending) {
    // Combine root_key and shared_secret
    unsigned char combined[64];
    memcpy(combined, root_key.data(), crypto_kdf_KEYBYTES);
    memcpy(combined + crypto_kdf_KEYBYTES, shared_secret, crypto_scalarmult_BYTES);

    unsigned char master_key[crypto_kdf_KEYBYTES];

    // Hash combined keys to get new master key
    crypto_generichash(master_key, crypto_kdf_KEYBYTES, combined, sizeof combined, nullptr, 0);

    // Derive new root_key using ROOT context
    if (crypto_kdf_derive_from_key(root_key.data(), crypto_kdf_KEYBYTES, 1, ROOT_CTX, master_key) != 0) {
        throw std::runtime_error("Failed to derive new root key");
    }

    // Derive chain key using CHAIN context
    if (crypto_kdf_derive_from_key(chain_key, crypto_kdf_KEYBYTES, 2, CHAIN_CTX, master_key) != 0) {
        throw std::runtime_error("Failed to derive chain key");
    }
}

std::vector<unsigned char> DoubleRatchet::derive_message_key(unsigned char* chain_key) {
    // Derive message key from chain key
    std::vector<unsigned char> message_key(crypto_kdf_KEYBYTES);
    if (crypto_kdf_derive_from_key(message_key.data(), crypto_kdf_KEYBYTES, 1, MSG_CTX, chain_key) != 0) {
        throw std::runtime_error("Failed to derive message key");
    }

    // Update chain key for next message
    if (crypto_kdf_derive_from_key(chain_key, crypto_kdf_KEYBYTES, 2, CHAIN_CTX, chain_key) != 0) {
        throw std::runtime_error("Failed to update chain key");
    }
    
    return message_key;
}

DeviceMessage DoubleRatchet::message_send(const unsigned char* message) {
    if (send_chain.index == 0) {
        dh_ratchet(nullptr, true);
    }

    DeviceMessage device_message;
    device_message.header = std::make_shared<MessageHeader>();
    device_message.header->dh_public.resize(crypto_kx_PUBLICKEYBYTES);
    std::copy(local_dh_public.begin(), local_dh_public.end(), device_message.header->dh_public.begin());
    device_message.header->prev_chain_length = prev_send_chain_length;
    device_message.header->message_index = send_chain.index;

    std::vector<unsigned char> message_key = derive_message_key(send_chain.chain_key);
    std::cout << "[DEBUG] Sender derived message key: " << bin2hex(message_key.data(), crypto_kdf_KEYBYTES) << std::endl;
    std::cout.flush();
    send_chain.index++;

    size_t msg_len = strlen(reinterpret_cast<const char*>(message));
    device_message.ciphertext = encrypt_message_given_key(message, msg_len, message_key.data());
    device_message.length = device_message.ciphertext.size();

    return device_message;
}

std::vector<unsigned char> DoubleRatchet::message_receive(const DeviceMessage& encrypted_message) {
    SkippedMessageKey skipped_key_id = {
        encrypted_message.header->dh_public,
        encrypted_message.header->message_index
    };
    auto it = skipped_message_keys.find(skipped_key_id);
    if (it != skipped_message_keys.end()) {
        std::vector<unsigned char> plaintext = decrypt_message_given_key(
            encrypted_message.ciphertext.data(), 
            encrypted_message.ciphertext.size(), 
            it->second.data()
        );
        skipped_message_keys.erase(it);
        return plaintext;
    }

    bool new_ratchet = encrypted_message.header->dh_public != std::vector<unsigned char>(remote_dh_public.begin(), remote_dh_public.end());
    if (new_ratchet) {
        std::cout << "New DH ratchet key detected" << std::endl;
        
        // skip any messages from the current receiving chain that we haven't received yet
        if (recv_chain.index > 0) {
            std::cout << "Caching skipped message keys from current chain (" << recv_chain.index 
                      << " to " << (encrypted_message.header->prev_chain_length - 1) << ")" << std::endl;
            
            // skip current receive chain
            for (int i = recv_chain.index; i < encrypted_message.header->prev_chain_length; i++) {
                std::vector<unsigned char> skipped_key = derive_message_key(recv_chain.chain_key);
                
                SkippedMessageKey key_id = {{0}, i};
                memcpy(key_id.dh_public.data(), remote_dh_public.data(), crypto_kx_PUBLICKEYBYTES);
                
                skipped_message_keys[key_id] = std::move(skipped_key);
                
                std::cout << "  Cached key for message " << i << " in previous chain: " 
                          << bin2hex(skipped_key.data(), crypto_kdf_KEYBYTES) << std::endl;
                
                // enforce maximum cache size by removing oldest keys if needed
                if (skipped_message_keys.size() > MAX_SKIPPED_MESSAGE_KEYS) {
                    skipped_message_keys.erase(skipped_message_keys.begin());
                    std::cout << "  Removed oldest key from cache due to size limit" << std::endl;
                }
            }
        }
        
        // perform DH ratchet with the new key
        dh_ratchet(encrypted_message.header->dh_public.data(), false);
        
        // reset receive chain index
        recv_chain.index = 0;
    }
    
    // skip any messages in the current chain that we haven't processed yet
    if (encrypted_message.header->message_index > recv_chain.index) {
        std::cout << "Skipping ahead in receive chain from " << recv_chain.index 
                  << " to " << encrypted_message.header->message_index << std::endl;
        
        // Store the original chain key so we can restore it after caching skipped keys
        unsigned char original_chain_key[crypto_kdf_KEYBYTES];
        memcpy(original_chain_key, recv_chain.chain_key, crypto_kdf_KEYBYTES);
        
        // Cache skipped message keys
        for (int i = recv_chain.index; i < encrypted_message.header->message_index; i++) {
            std::vector<unsigned char> skipped_key = derive_message_key(recv_chain.chain_key);
            
            SkippedMessageKey key_id = {{0}, i};
            memcpy(key_id.dh_public.data(), encrypted_message.header->dh_public.data(), crypto_kx_PUBLICKEYBYTES);
            
            skipped_message_keys[key_id] = std::move(skipped_key);
            
            std::cout << "  Cached key for skipped message " << i << ": " 
                      << bin2hex(skipped_key.data(), crypto_kdf_KEYBYTES) << std::endl;
            
            // enforce maximum cache size
            if (skipped_message_keys.size() > MAX_SKIPPED_MESSAGE_KEYS) {
                skipped_message_keys.erase(skipped_message_keys.begin());
                std::cout << "  Removed oldest key from cache due to size limit" << std::endl;
            }
        }
        
        // restore the original chain key state before generating the message key
        memcpy(recv_chain.chain_key, original_chain_key, crypto_kdf_KEYBYTES);
        
        // advance the chain to the current message index
        for (int i = recv_chain.index; i < encrypted_message.header->message_index; i++) {
            unsigned char temp_key[crypto_kdf_KEYBYTES];
            if (crypto_kdf_derive_from_key(temp_key, crypto_kdf_KEYBYTES, 1, MSG_CTX, recv_chain.chain_key) != 0) {
                throw std::runtime_error("Failed to derive temporary message key");
            }
            
            // update chain key
            if (crypto_kdf_derive_from_key(recv_chain.chain_key, crypto_kdf_KEYBYTES, 2, CHAIN_CTX, recv_chain.chain_key) != 0) {
                throw std::runtime_error("Failed to update chain key");
            }
        }
    }
    
    // generate the message key
    std::vector<unsigned char> message_key = derive_message_key(recv_chain.chain_key);
    std::cout << "[DEBUG] Receiver derived message key: " << bin2hex(message_key.data(), crypto_kdf_KEYBYTES) << std::endl;
    std::cout.flush();
    
    // update the receive chain index
    recv_chain.index = encrypted_message.header->message_index + 1;

    // Decrypt the message
    return decrypt_message_given_key(encrypted_message.ciphertext.data(), encrypted_message.ciphertext.size(), message_key.data());
}

const unsigned char* DoubleRatchet::get_public_key() const {
    return local_dh_public.data();
}

void DoubleRatchet::print_state() const {
    std::cout << "Root key: " << bin2hex(root_key.data(), crypto_kdf_KEYBYTES) << std::endl;
    std::cout << "Send chain (index " << send_chain.index << "): " 
              << bin2hex(send_chain.chain_key, crypto_kdf_KEYBYTES) << std::endl;
    std::cout << "Recv chain (index " << recv_chain.index << "): " 
              << bin2hex(recv_chain.chain_key, crypto_kdf_KEYBYTES) << std::endl;
    std::cout << "Previous send chain length: " << prev_send_chain_length << std::endl;
    std::cout << "Skipped message keys in cache: " << skipped_message_keys.size() << std::endl;
}
