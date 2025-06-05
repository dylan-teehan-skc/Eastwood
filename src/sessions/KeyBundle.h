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
    virtual ~KeyBundle() {
        std::cout << "Removing base key bundle class" << std::endl;
    };

    KeyBundle(std::array<unsigned char, 32> my_device_public_in,
        std::array<unsigned char, 32> their_device_public_in){
        my_device_public = my_device_public_in;
        their_device_public = their_device_public_in;
    };

    virtual Role get_role() const = 0;

    virtual std::array<unsigned char, 32> get_shared_secret() = 0;

    std::array<unsigned char, 32> get_my_device_public() const { return my_device_public; }
    std::array<unsigned char, 32> get_their_device_public() const { return their_device_public; }

    virtual std::unique_ptr<NewRatchet> create_ratchet() = 0;
protected:
    std::array<unsigned char, 32> my_device_public;
    std::array<unsigned char, 32> their_device_public;
};

class SendingKeyBundle: public KeyBundle {
public:
    ~SendingKeyBundle() {
        std::cout << "Removing sending key bundle sub-class" << std::endl;
    }
    SendingKeyBundle(
                std::array<unsigned char, 32> my_device_public_in,
                std::array<unsigned char, 32> my_ephemeral_public_in,
                std::shared_ptr<SecureMemoryBuffer> my_ephemeral_private_in,
                std::array<unsigned char, 32> their_device_public_in,
                std::array<unsigned char, 32> their_signed_public_in,
                std::optional<std::array<unsigned char, 32>> their_onetime_public_in,
                std::array<unsigned char, 64> their_signed_signature_in
            ) : KeyBundle(my_device_public_in, their_device_public_in) {
        my_ephemeral_public = my_ephemeral_public_in;
        my_ephemeral_private = std::move(my_ephemeral_private_in);
        their_signed_public = their_signed_public_in;
        their_onetime_public = their_onetime_public_in;
        their_signed_signature = their_signed_signature_in;
    };

    Role get_role() const override { return Role::Initiator; }

    std::array<unsigned char, 32> get_shared_secret() override {
        std::cout << "\n===== SENDING KEY BUNDLE DEBUG =====" << std::endl;
        
        // Get keys from database and show them
        auto my_device_private_key = get_my_device_private();
        auto my_device_public_key = get_public_key("device");
        
        // Verify the signature
        int result = crypto_sign_verify_detached(
                their_signed_signature.data(),
                their_signed_public.data(),
                crypto_box_PUBLICKEYBYTES,
                their_device_public.data());
        
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
    std::array<unsigned char, 32> get_my_ephemeral_public() const { return my_ephemeral_public; }
    const std::shared_ptr<SecureMemoryBuffer>& get_my_ephemeral_private() const { return my_ephemeral_private; }
    std::array<unsigned char, 32> get_their_signed_public() const { return their_signed_public; }
    std::optional<std::array<unsigned char, 32>> get_their_onetime_public() const { return their_onetime_public; }
    std::array<unsigned char, 64> get_their_signed_signature() const { return their_signed_signature; }

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
    std::array<unsigned char, 32> my_ephemeral_public;
    std::shared_ptr<SecureMemoryBuffer> my_ephemeral_private;
    std::array<unsigned char, 32> their_signed_public;
    std::optional<std::array<unsigned char, 32>> their_onetime_public;
    std::array<unsigned char, 64> their_signed_signature;
};

class ReceivingKeyBundle: public KeyBundle {
public:
    ~ReceivingKeyBundle() {
        std::cout << "Removing receiving key bundle sub-class" << std::endl;
    }
    ReceivingKeyBundle(
                std::array<unsigned char, 32> their_device_public_in,
                std::array<unsigned char, 32> their_ephemeral_public_in,
                std::array<unsigned char, 32> my_device_public_in,
                std::optional<std::array<unsigned char, 32>> my_onetime_public_in
            ): KeyBundle(my_device_public_in, their_device_public_in) {
        their_ephemeral_public = their_ephemeral_public_in;
        my_onetime_public = my_onetime_public_in;
    };

    Role get_role() const override { return Role::Responder; }

    std::array<unsigned char, 32> get_shared_secret() override {
        std::cout << "\n===== RECEIVING KEY BUNDLE DEBUG =====" << std::endl;
        
        // Get keys from database and show them
        auto my_device_private_key = get_my_device_private();
        auto my_device_public_key = get_public_key("device");
        auto my_signed_private_key = get_my_signed_private();
        auto my_signed_public_key = get_public_key("signed");

        std::optional<std::unique_ptr<SecureMemoryBuffer>> my_onetime_private_opt = std::nullopt;
        if (my_onetime_public.has_value()) {
            my_onetime_private_opt = get_my_onetime_private(my_onetime_public.value());
        }

        return x3dh_responder(
                their_device_public,
                their_ephemeral_public,
                get_my_device_private(),
                get_my_signed_private(),
                std::move(my_onetime_private_opt)
            );
    };

    // Getters for private attributes
    std::array<unsigned char, 32> get_their_ephemeral_public() const { return their_ephemeral_public; }
    static std::unique_ptr<SecureMemoryBuffer> get_my_device_private() { return get_decrypted_sk("device"); }
    static std::unique_ptr<SecureMemoryBuffer> get_my_signed_private() { return get_decrypted_sk("signed"); }
    static std::unique_ptr<SecureMemoryBuffer> get_my_onetime_private(const std::array<unsigned char, 32> &my_onetime_public) { return get_onetime_private_key(my_onetime_public.data()); }

    std::unique_ptr<NewRatchet> create_ratchet() override {
        return std::make_unique<NewRatchet>(get_shared_secret(), their_ephemeral_public);
    };
private:
    std::array<unsigned char, 32> their_ephemeral_public;
    std::optional<std::array<unsigned char, 32>> my_onetime_public;
};

#endif //KEYBUNDLE_H
