//
// Created by Josh Sloggett on 28/05/2025.
//

#ifndef KEYBUNDLE_H
#define KEYBUNDLE_H
#include "src/key_exchange/x3dh.h"

enum Role {
    Initiator,
    Responder
};

class KeyBundle {
    public:
    virtual ~KeyBundle() = default;

    KeyBundle(){

    };

    virtual Role get_role() const = 0;

    virtual unsigned char* get_shared_secret() = 0;
};

class SendingKeyBundle: public KeyBundle {
public:
    SendingKeyBundle(
                unsigned char* my_device_public_in,
                unsigned char* my_device_private_in,
                unsigned char* my_ephemeral_public_in,
                unsigned char* my_ephemeral_private_in,
                unsigned char* their_device_public_in,
                unsigned char* their_signed_public_in,
                unsigned char* their_onetime_public_in,
                unsigned char* their_signed_signature_in
            ) {
        my_device_public = my_device_public_in;
        my_device_private = my_device_private_in;
        my_ephemeral_public = my_ephemeral_public_in;
        my_ephemeral_private = my_ephemeral_private_in;
        their_device_public = their_device_public_in;
        their_signed_public = their_signed_public_in;
        their_onetime_public = their_onetime_public_in;
        their_signed_signature = their_signed_signature_in;
    };

    Role get_role() const override { return Role::Initiator; }

    unsigned char *get_shared_secret() override {
        return x3dh_initiator(
                my_device_private,
                my_ephemeral_private,
                their_device_public,
                their_signed_public,
                their_onetime_public,
                their_signed_signature
            );
    };

    // Getters for private attributes
    unsigned char* get_my_device_private() const { return my_device_private; }
    unsigned char* get_my_device_public() const { return my_device_public; }
    unsigned char* get_my_ephemeral_public() const { return my_ephemeral_public; }
    unsigned char* get_my_ephemeral_private() const { return my_ephemeral_private; }
    unsigned char* get_their_device_public() const { return their_device_public; }
    unsigned char* get_their_signed_public() const { return their_signed_public; }
    unsigned char* get_their_onetime_public() const { return their_onetime_public; }
    unsigned char* get_their_signed_signature() const { return their_signed_signature; }

private:
    unsigned char* my_device_public;
    unsigned char* my_device_private;
    unsigned char* my_ephemeral_public;
    unsigned char* my_ephemeral_private;
    unsigned char* their_device_public;
    unsigned char* their_signed_public;
    unsigned char* their_onetime_public;
    unsigned char* their_signed_signature;
};

class ReceivingKeyBundle: public KeyBundle {
public:
    ReceivingKeyBundle(
                unsigned char* their_device_public_in,
                unsigned char* their_ephemeral_public_in,
                unsigned char* my_device_public_in,
                unsigned char* my_device_private_in,
                unsigned char* my_signed_private_in,
                unsigned char* my_onetime_private_in
            ) {
        their_device_public = their_device_public_in;
        their_ephemeral_public = their_ephemeral_public_in;
        my_device_public = my_device_public_in;
        my_device_private = my_device_private_in;
        my_signed_private = my_signed_private_in;
        my_onetime_private = my_onetime_private_in;
    };

    Role get_role() const override { return Role::Responder; }

    unsigned char *get_shared_secret() override {
        return x3dh_responder(
                their_device_public,
                their_ephemeral_public,
                my_device_private,
                my_signed_private,
                my_onetime_private
            );
    };

    // Getters for private attributes
    unsigned char* get_their_device_public() const { return their_device_public; }
    unsigned char* get_their_ephemeral_public() const { return their_ephemeral_public; }
    unsigned char* get_my_device_public() const { return my_device_public; }
    unsigned char* get_my_device_private() const { return my_device_private; }
    unsigned char* get_my_signed_private() const { return my_signed_private; }
    unsigned char* get_my_onetime_private() const { return my_onetime_private; }

private:
    unsigned char* their_device_public;
    unsigned char* their_ephemeral_public;
    unsigned char* my_device_public;
    unsigned char* my_device_private;
    unsigned char* my_signed_private;
    unsigned char* my_onetime_private;
};

#endif //KEYBUNDLE_H
