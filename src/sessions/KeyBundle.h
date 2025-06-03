//
// Created by Josh Sloggett on 28/05/2025.
//

#ifndef KEYBUNDLE_H
#define KEYBUNDLE_H
#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>

#include "src/key_exchange/NewRatchet.h"
#include "src/key_exchange/x3dh.h"
#include "src/sql/queries.h"
#include "src/key_exchange/utils.h"

enum Role {
    Initiator,
    Responder
};

class KeyBundle {
    public:
    virtual ~KeyBundle() = default;

    KeyBundle(unsigned char* my_device_public_in,
        unsigned char* their_device_public_in){
        my_device_public = my_device_public_in;
        their_device_public = their_device_public_in;
    };

    virtual Role get_role() const = 0;

    virtual unsigned char* get_shared_secret() = 0;

    unsigned char *get_my_device_public() const { return my_device_public; }
    unsigned char *get_their_device_public() const { return their_device_public; }

    virtual std::unique_ptr<NewRatchet> create_ratchet() = 0;
protected:
    unsigned char *my_device_public;
    unsigned char *their_device_public;
};

class SendingKeyBundle: public KeyBundle {
public:
    SendingKeyBundle(
                unsigned char* my_device_public_in,
                unsigned char* my_ephemeral_public_in,
                std::shared_ptr<SecureMemoryBuffer> my_ephemeral_private_in,
                unsigned char* their_device_public_in,
                unsigned char* their_signed_public_in,
                unsigned char* their_onetime_public_in,
                unsigned char* their_signed_signature_in
            ) : KeyBundle(my_device_public_in, their_device_public_in) {
        my_ephemeral_public = my_ephemeral_public_in;
        my_ephemeral_private = std::move(my_ephemeral_private_in);
        their_signed_public = their_signed_public_in;
        their_onetime_public = their_onetime_public_in;
        their_signed_signature = their_signed_signature_in;
    };

    Role get_role() const override { return Role::Initiator; }

    unsigned char *get_shared_secret() override {
        std::cout << "\n===== SENDING KEY BUNDLE DEBUG =====" << std::endl;
        
        // Get keys from database and show them
        auto my_device_private_key = get_my_device_private();
        auto my_device_public_key = get_public_key("device");
        
        std::cout << "INITIATOR KEYS FROM DATABASE:" << std::endl;
        std::cout << "  my_device_public: " << bin2hex(reinterpret_cast<const unsigned char*>(my_device_public_key.constData()), 32) << std::endl;
        std::cout << "  my_device_private: " << bin2hex(my_device_private_key->data(), 32) << std::endl;
        std::cout << "  my_ephemeral_public: " << bin2hex(my_ephemeral_public, 32) << std::endl;
        std::cout << "  my_ephemeral_private: " << bin2hex(my_ephemeral_private->data(), 32) << std::endl;
        
        std::cout << "RECIPIENT KEYS RECEIVED:" << std::endl;
        std::cout << "  their_device_public: " << bin2hex(their_device_public, 32) << std::endl;
        std::cout << "  their_signed_public: " << bin2hex(their_signed_public, 32) << std::endl;
        std::cout << "  their_signed_signature: " << bin2hex(their_signed_signature, 64) << std::endl;
        if (their_onetime_public) {
            std::cout << "  their_onetime_public: " << bin2hex(their_onetime_public, 32) << std::endl;
        } else {
            std::cout << "  their_onetime_public: NULL" << std::endl;
        }
        
        // Verify the signature
        int result = crypto_sign_verify_detached(
                their_signed_signature,
                their_signed_public,
                crypto_box_PUBLICKEYBYTES,
                their_device_public);
        
        std::cout << "Signature verification result: " << (result == 0 ? "VALID" : "INVALID") << std::endl;
        
        if (result != 0) {
            throw std::runtime_error("Invalid signature on signed prekey");
        }

        return x3dh_initiator(
                get_my_device_private(),
                get_my_ephemeral_private(),
                their_device_public,
                their_signed_public,
                their_onetime_public
                );
    };

    // Getters for private attributes
    std::unique_ptr<SecureMemoryBuffer> get_my_device_private() const { return get_decrypted_sk("device"); }
    unsigned char* get_my_ephemeral_public() const { return my_ephemeral_public; }
    const std::shared_ptr<SecureMemoryBuffer>& get_my_ephemeral_private() const { return my_ephemeral_private; }
    unsigned char* get_their_signed_public() const { return their_signed_public; }
    unsigned char* get_their_onetime_public() const { return their_onetime_public; }
    unsigned char* get_their_signed_signature() const { return their_signed_signature; }

    std::unique_ptr<NewRatchet> create_ratchet() override {
        // Use the overloaded constructor to ensure the ephemeral keypair is used for the initial ratchet state
        return std::make_unique<NewRatchet>(
            get_shared_secret(),
            their_signed_public,
            my_ephemeral_public,
            my_ephemeral_private
        );
    };

private:
    unsigned char* my_ephemeral_public;
    std::shared_ptr<SecureMemoryBuffer> my_ephemeral_private;
    unsigned char* their_signed_public;
    unsigned char* their_onetime_public = nullptr;
    unsigned char* their_signed_signature;
};

class ReceivingKeyBundle: public KeyBundle {
public:
    ReceivingKeyBundle(
                unsigned char* their_device_public_in,
                unsigned char* their_ephemeral_public_in,
                unsigned char* my_device_public_in,
                unsigned char* my_onetime_public_in
            ): KeyBundle(my_device_public_in, their_device_public_in) {
        their_ephemeral_public = their_ephemeral_public_in;
        my_onetime_public = my_onetime_public_in;
    };

    Role get_role() const override { return Role::Responder; }

    unsigned char *get_shared_secret() override {
        std::cout << "\n===== RECEIVING KEY BUNDLE DEBUG =====" << std::endl;
        
        // Get keys from database and show them
        auto my_device_private_key = get_my_device_private();
        auto my_device_public_key = get_public_key("device");
        auto my_signed_private_key = get_my_signed_private();
        auto my_signed_public_key = get_public_key("signed");
        
        std::cout << "RESPONDER KEYS FROM DATABASE:" << std::endl;
        std::cout << "  my_device_public: " << bin2hex(reinterpret_cast<const unsigned char*>(my_device_public_key.constData()), 32) << std::endl;
        std::cout << "  my_device_private: " << bin2hex(my_device_private_key->data(), 32) << std::endl;
        std::cout << "  my_signed_public: " << bin2hex(reinterpret_cast<const unsigned char*>(my_signed_public_key.constData()), 32) << std::endl;
        std::cout << "  my_signed_private: " << bin2hex(my_signed_private_key->data(), 32) << std::endl;
        
        if (my_onetime_public) {
            auto my_onetime_private_key = get_my_onetime_private(my_onetime_public);
            std::cout << "  my_onetime_public: " << bin2hex(my_onetime_public, 32) << std::endl;
            std::cout << "  my_onetime_private: " << bin2hex(my_onetime_private_key->data(), 32) << std::endl;
        } else {
            std::cout << "  my_onetime_public: NULL" << std::endl;
            std::cout << "  my_onetime_private: NULL" << std::endl;
        }
        
        std::cout << "INITIATOR KEYS RECEIVED:" << std::endl;
        std::cout << "  their_device_public: " << bin2hex(their_device_public, 32) << std::endl;
        std::cout << "  their_ephemeral_public: " << bin2hex(their_ephemeral_public, 32) << std::endl;
        
        return x3dh_responder(
                their_device_public,
                their_ephemeral_public,
                get_my_device_private(),
                get_my_signed_private(),
                get_my_onetime_private(my_onetime_public)
            );
    };

    // Getters for private attributes
    unsigned char* get_their_ephemeral_public() const { return their_ephemeral_public; }
    static std::unique_ptr<SecureMemoryBuffer> get_my_device_private() { return get_decrypted_sk("device"); }
    static std::unique_ptr<SecureMemoryBuffer> get_my_signed_private() { return get_decrypted_sk("signed"); }
    static std::unique_ptr<SecureMemoryBuffer> get_my_onetime_private(const unsigned char* my_onetime_public) { return get_onetime_private_key(my_onetime_public); }

    std::unique_ptr<NewRatchet> create_ratchet() override {
        return std::make_unique<NewRatchet>(get_shared_secret(), their_ephemeral_public);
    };
private:
    unsigned char* their_ephemeral_public;
    unsigned char* my_onetime_public = nullptr;
};

#endif //KEYBUNDLE_H
