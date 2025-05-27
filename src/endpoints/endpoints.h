#ifndef ENDPOINTS_H
#define ENDPOINTS_H
#include <string>
#include <sodium.h>

#include "src/algorithms/constants.h"
#include "src/sessions/SessionManager.h"

void post_register_user(
    const std::string &username,
    unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES],
    unsigned char registration_nonce[NONCE_LEN],
    unsigned char nonce_signature[crypto_sign_BYTES]
);


void post_register_device(
    unsigned char pk_id[crypto_sign_PUBLICKEYBYTES],
    unsigned char pk_device[crypto_sign_PUBLICKEYBYTES],
    unsigned char pk_signature[crypto_sign_BYTES]
);

keyBundleRequest get_keybundles(
    unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES]
    );

#endif //ENDPOINTS_H
