//
// Created by Fred Sheppard on 22/05/2025.
//

#ifndef ALGORITHMS_H
#define ALGORITHMS_H
#include "constants.h"
#include <sodium.h>

int derive_master_key(
    unsigned char master_key[MASTER_KEY_LEN],
    const char *master_password,
    size_t password_len,
    unsigned char salt[crypto_pwhash_SALTBYTES]
);

void encrypt_kek(
    unsigned char encrypted_kek[KEK_LEN + ENC_OVERHEAD],
    unsigned char kek[KEK_LEN],
    unsigned char nonce[NONCE_LEN],
    unsigned char master_key[MASTER_KEY_LEN]
);

void encrypt_secret_key(
    unsigned char encrypted_sk[crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD],
    unsigned char sk[crypto_sign_SECRETKEYBYTES],
    unsigned char nonce[NONCE_LEN],
    unsigned char master_key[MASTER_KEY_LEN]
);

int decrypt_kek(
    unsigned char decrypted_kek[KEK_LEN],
    unsigned char encrypted_kek[KEK_LEN + ENC_OVERHEAD],
    unsigned char nonce[NONCE_LEN],
    unsigned char master_key[MASTER_KEY_LEN]
);

int decrypt_secret_key(
    unsigned char decrypted_sk[crypto_sign_SECRETKEYBYTES],
    const unsigned char encrypted_sk[crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD],
    const unsigned char nonce[NONCE_LEN],
    const unsigned char key[MASTER_KEY_LEN]
);

#endif //ALGORITHMS_H
