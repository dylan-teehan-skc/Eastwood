//
// Created by Josh Sloggett on 31/05/2025.
//

#pragma once

#include "sodium.h"
#include <cstring>

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

