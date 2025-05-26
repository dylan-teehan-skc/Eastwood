#ifndef DOUBLERATCHET_H
#define DOUBLERATCHET_H

#include <cstring>
#include <sodium.h>
#include <stdexcept>
#include <iostream>
#include <map>
#include <vector>
#include <memory>

struct Chain {
    unsigned char chain_key[crypto_kdf_KEYBYTES];
    int index;

    template<class Archive>
    void serialize(Archive& ar) {
        ar(chain_key, index);
    }
};

// Message header structure as per Double Ratchet specification
struct MessageHeader {
    std::vector<unsigned char> dh_public; // Sender's current ratchet public key
    int prev_chain_length;
    int message_index;

    template<class Archive>
    void serialize(Archive& ar) {
        ar(dh_public, prev_chain_length, message_index);
    }
};

struct Message {
    std::shared_ptr<MessageHeader> header;
    std::vector<unsigned char> message;

    template<class Archive>
    void serialize(Archive& ar) {
        ar(header, message);
    }
};

// Structure to identify a skipped message
struct SkippedMessageKey {
    std::vector<unsigned char> dh_public;
    int message_index;
    
    bool operator<(const SkippedMessageKey& other) const {
        int cmp = std::memcmp(dh_public.data(), other.dh_public.data(), dh_public.size());
        if (cmp != 0) return cmp < 0;
        return message_index < other.message_index;
    }

    template<class Archive>
    void serialize(Archive& ar) {
        ar(dh_public, message_index);
    }
};

// Common message class for device communication
class DeviceMessage {
public:
    std::shared_ptr<MessageHeader> header;
    std::vector<unsigned char> ciphertext;
    size_t length;

    template<class Archive>
    void serialize(Archive& ar) {
        ar(header, ciphertext, length);
    }

    DeviceMessage() : header(std::make_shared<MessageHeader>()), length(0) {}
    // Use default copy/move/destructor
    DeviceMessage(const DeviceMessage&) = default;
    DeviceMessage(DeviceMessage&&) noexcept = default;
    DeviceMessage& operator=(const DeviceMessage&) = default;
    DeviceMessage& operator=(DeviceMessage&&) noexcept = default;
    ~DeviceMessage() = default;
};

class DoubleRatchet {
public:
    DoubleRatchet(); // Default constructor for Cereal
    DoubleRatchet(const unsigned char* x3dh_root_key,
                  const unsigned char* remote_public_signed_prekey,
                  const unsigned char* local_public_ephemeral,
                  const unsigned char* local_private_ephemeral);
    
    ~DoubleRatchet();

    template<class Archive>
    void serialize(Archive& ar) {
        ar(send_chain, recv_chain, root_key, local_dh_private, local_dh_public, 
           prev_send_chain_length, remote_dh_public, skipped_message_keys);
    }

    // Creates a message key and header for sending
    DeviceMessage message_send(const unsigned char* message);

    // Processes a received message with header and returns the decrypted plaintext
    std::vector<unsigned char> message_receive(const DeviceMessage& encrypted_message);

    const unsigned char* get_public_key() const;
    const std::vector<unsigned char>& getRootKey() const { return root_key; }
    void print_state() const;

private:
    // Performs a Diffie-Hellman ratchet step and updates the root key and chain key
    void dh_ratchet(const unsigned char* remote_public_key, bool is_sending);
    
    // Derive a new set of keys (root key and chain key) from DH output
    void kdf_ratchet(const unsigned char* shared_secret, unsigned char* chain_key, bool is_sending);
    
    // Derive a message key from a chain key and updates the chain key
    static std::vector<unsigned char> derive_message_key(unsigned char* chain_key);

    std::vector<unsigned char> root_key;
    std::vector<unsigned char> local_dh_public;
    std::vector<unsigned char> local_dh_private;
    std::vector<unsigned char> remote_dh_public;

    Chain send_chain{};
    Chain recv_chain{};
    int prev_send_chain_length; // Length of previous sending chain

    // Cache of message keys for skipped/out-of-order messages
    std::map<SkippedMessageKey, std::vector<unsigned char>> skipped_message_keys;
    // Maximum number of skipped message keys to keep in memory
    static constexpr int MAX_SKIPPED_MESSAGE_KEYS = 100;
};

#endif //DOUBLERATCHET_H
