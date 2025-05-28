#ifndef ENDPOINTS_H
#define ENDPOINTS_H
#include <string>
#include <sodium.h>

#include "src/algorithms/constants.h"
#include "src/keys/secure_memory_buffer.h"
#include "src/key_exchange/DoubleRatchet.h"

void post_register_user(
    const std::string &username,
    const unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES],
    const unsigned char registration_nonce[CHA_CHA_NONCE_LEN],
    const unsigned char nonce_signature[crypto_sign_BYTES]
);


void post_register_device(
    const unsigned char pk_id[crypto_sign_PUBLICKEYBYTES],
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    const unsigned char pk_signature[crypto_sign_BYTES]
);

std::vector<unsigned char> post_request_login(
    std::string username,
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES]
);

std::string post_authenticate(
    std::string username,
    const unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    unsigned char signature[crypto_sign_BYTES]
);

void post_ratchet_message(
    const DeviceMessage *msg
);

void post_handshake_device(
    const unsigned char *recipient_device_key_public,
    const unsigned char *recipient_signed_prekey_public,
    const unsigned char *recipient_onetime_prekey_public,
    const unsigned char *my_device_key_public,
    const unsigned char *my_ephemeral_key_public
);

void get_messages();

void get_keybundles(
    unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES]
);

#endif //ENDPOINTS_H
