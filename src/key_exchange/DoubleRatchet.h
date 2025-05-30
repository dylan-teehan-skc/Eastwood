#ifndef DOUBLERATCHET_H
#define DOUBLERATCHET_H

#include <cstring>
#include <sodium.h>
#include <stdexcept>
#include <iostream>
#include <map>
#include <vector>

#include "src/sessions/KeyBundle.h"

struct Chain {
    unsigned char chain_key[crypto_kdf_KEYBYTES];
    int index;
};

// Message header structure as per Double Ratchet specification
struct MessageHeader {
    unsigned char dh_public[crypto_kx_PUBLICKEYBYTES]; // Sender's current ratchet public key
    int prev_chain_length;                             // Length of previous sending chain
    int message_index;                                 // Message number in the chain
    unsigned char device_id[crypto_box_PUBLICKEYBYTES]; // Fixed-size array for device ID
};

struct Message {
    MessageHeader *header;
    unsigned char* message;
};

// Structure to identify a skipped message
struct SkippedMessageKey {
    unsigned char dh_public[crypto_kx_PUBLICKEYBYTES];
    int message_index;
    
    // Comparison operator for map
    bool operator<(const SkippedMessageKey& other) const {
        int cmp = memcmp(dh_public, other.dh_public, crypto_kx_PUBLICKEYBYTES);
        if (cmp != 0) return cmp < 0;
        return message_index < other.message_index;
    }
};

// Common message class for device communication
class DeviceMessage {
public:
    DeviceMessage() : header(nullptr), ciphertext(nullptr), length(0) {}
    
    ~DeviceMessage() {
        if (header) delete header;
        if (ciphertext) delete[] ciphertext;
    }
    
    // Copy constructor
    DeviceMessage(const DeviceMessage& other) {
        if (other.header) {
            header = new MessageHeader();
            memcpy(header->dh_public, other.header->dh_public, crypto_kx_PUBLICKEYBYTES);
            header->prev_chain_length = other.header->prev_chain_length;
            header->message_index = other.header->message_index;
        } else {
            header = nullptr;
        }
        
        if (other.ciphertext) {
            ciphertext = new unsigned char[other.length];
            memcpy(ciphertext, other.ciphertext, other.length);
        } else {
            ciphertext = nullptr;
        }
        
        length = other.length;
    }
    
    // Move constructor
    DeviceMessage(DeviceMessage&& other) noexcept 
        : header(other.header), ciphertext(other.ciphertext), length(other.length) {
        other.header = nullptr;
        other.ciphertext = nullptr;
        other.length = 0;
    }
    
    // Assignment operator
    DeviceMessage& operator=(const DeviceMessage& other) {
        if (this != &other) {
            if (header) delete header;
            if (ciphertext) delete[] ciphertext;
            
            if (other.header) {
                header = new MessageHeader();
                memcpy(header->dh_public, other.header->dh_public, crypto_kx_PUBLICKEYBYTES);
                header->prev_chain_length = other.header->prev_chain_length;
                header->message_index = other.header->message_index;
            } else {
                header = nullptr;
            }
            
            if (other.ciphertext) {
                ciphertext = new unsigned char[other.length];
                memcpy(ciphertext, other.ciphertext, other.length);
            } else {
                ciphertext = nullptr;
            }
            
            length = other.length;
        }
        return *this;
    }
    
    // Move assignment operator
    DeviceMessage& operator=(DeviceMessage&& other) noexcept {
        if (this != &other) {
            if (header) delete header;
            if (ciphertext) delete[] ciphertext;
            
            header = other.header;
            ciphertext = other.ciphertext;
            length = other.length;
            
            other.header = nullptr;
            other.ciphertext = nullptr;
            other.length = 0;
        }
        return *this;
    }
    
    MessageHeader* header;
    unsigned char* ciphertext;
    size_t length;
};

class DoubleRatchet {
public:
    DoubleRatchet(KeyBundle* bundle);
    
    ~DoubleRatchet();
    
    // Creates a message key and header for sending
    DeviceMessage message_send(const unsigned char* message, unsigned char* identity_session_id);

    // Processes a received message with header and returns the decrypted plaintext
    std::vector<unsigned char> message_receive(const DeviceMessage& encrypted_message);

    void print_state() const;

private:
    unsigned char ratchet_id[crypto_box_PUBLICKEYBYTES * 2]{};  // Changed from pointer to array
    unsigned char* other_device_id;
    // Performs a Diffie-Hellman ratchet step and updates the root key and chain key
    void dh_ratchet(const unsigned char* remote_public_key, bool is_sending);
    
    // Derive a new set of keys (root key and chain key) from DH output
    void kdf_ratchet(const unsigned char* shared_secret, unsigned char* chain_key, bool is_sending);
    
    // Derive a message key from a chain key and updates the chain key
    static unsigned char* derive_message_key(const unsigned char* chain_key);

    // Advance a chain key to the next state
    static void advance_chain_key(unsigned char* chain_key);

    void set_ratchet_id_and_initial_keys(KeyBundle* bundle);
    void derive_keys_from_dh_output(const unsigned char* dh_output, bool is_initiator);

    unsigned char root_key[crypto_kdf_KEYBYTES]{};

    Chain send_chain{};
    Chain recv_chain{};
    
    int prev_send_chain_length; // Length of previous sending chain

    unsigned char local_dh_public[crypto_kx_PUBLICKEYBYTES]{};
    unsigned char local_dh_private[crypto_kx_SECRETKEYBYTES]{};

    unsigned char remote_dh_public[crypto_kx_PUBLICKEYBYTES]{};
    
    // Cache of message keys for skipped/out-of-order messages
    std::map<SkippedMessageKey, unsigned char*> skipped_message_keys;
    
    // Maximum number of skipped message keys to keep in memory
    static constexpr int MAX_SKIPPED_MESSAGE_KEYS = 100;

    bool needs_dh_ratchet_on_send = false;

};

#endif //DOUBLERATCHET_H
