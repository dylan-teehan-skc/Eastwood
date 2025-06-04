#pragma once

#include <sodium.h>
#include <cstring>
#include <array>
#include <vector>

struct MessageHeader {
    // Constructor to ensure proper initialization
    MessageHeader() : dh_public{}, prev_chain_length(0), message_index(0), device_id{} {
        memset(file_uuid, 0, sizeof(file_uuid));
    }

    std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> dh_public; // Sender's current ratchet public key
    int prev_chain_length; // Length of previous sending chain
    int message_index; // Message number in the chain
    std::array<unsigned char, crypto_box_PUBLICKEYBYTES> device_id; // Fixed-size array for device ID
    char file_uuid[64]; // Fixed-size array instead of std::string
};

struct Message {
    MessageHeader header;
    std::vector<unsigned char> message;
};

// Common message class for device communication
class DeviceMessage {
public:
    DeviceMessage() : header{}, ciphertext(std::vector<unsigned char>()) {
    }

    ~DeviceMessage() = default;

    // Copy constructor
    DeviceMessage(const DeviceMessage &other)
        : header(other.header), ciphertext(other.ciphertext) {
    }

    // Move constructor
    DeviceMessage(DeviceMessage &&other) noexcept
        : header(std::move(other.header)), ciphertext(std::move(other.ciphertext)) {
    }

    // Assignment operator
    DeviceMessage &operator=(const DeviceMessage &other) {
        if (this != &other) {
            header = other.header;
            ciphertext = other.ciphertext;
        }
        return *this;
    }

    // Move assignment operator
    DeviceMessage &operator=(DeviceMessage &&other) noexcept {
        if (this != &other) {
            header = std::move(other.header);
            ciphertext = std::move(other.ciphertext);
        }
        return *this;
    }

    MessageHeader header;
    std::vector<unsigned char> ciphertext;
};
