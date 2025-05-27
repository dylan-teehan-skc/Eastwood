#include <cstdio>
#include <iostream>
#include <string>
#include <sodium.h>
#include "src/algorithms/algorithms.h"

#include "../../algorithms/constants.h"
#include "src/endpoints/endpoints.h"
#include "src/sql/queries.h"


int register_user(const std::string &username, const std::string &master_password) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium initialization failed\n");
        return 1;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);

    unsigned char master_key[MASTER_KEY_LEN];
    if (derive_master_key(
            master_key,
            master_password.c_str(),
            master_password.length(),
            salt) != 0) {
        fprintf(stderr, "Password hashing failed\n");
        return 1;
    }

    unsigned char kek[KEK_LEN];
    crypto_secretbox_keygen(kek);

    unsigned char nonce_kek[NONCE_LEN];
    randombytes_buf(nonce_kek, sizeof(nonce_kek));

    unsigned char encrypted_kek[KEK_LEN + ENC_OVERHEAD];
    encrypt_kek(encrypted_kek, kek, nonce_kek, master_key);

    save_encrypted_key("kek", encrypted_kek, nonce_kek);
    // TODO: send_request("POST", "/add_kek", kek, nonce_kek);

    unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk_identity[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk_identity, sk_identity);

    unsigned char nonce_sk[NONCE_LEN];
    randombytes_buf(nonce_sk, NONCE_LEN);

    unsigned char encrypted_sk[crypto_sign_SECRETKEYBYTES + ENC_OVERHEAD];
    encrypt_secret_key(encrypted_sk, sk_identity, nonce_sk, master_key);

    unsigned char registration_nonce[NONCE_LEN];
    randombytes_buf(registration_nonce, sizeof(registration_nonce));

    unsigned char nonce_signature[crypto_sign_BYTES];
    crypto_sign_detached(nonce_signature, nullptr, registration_nonce, NONCE_LEN, sk_identity);

    save_keypair("identity", pk_identity, encrypted_sk, nonce_sk);

    post_register_user(username, pk_identity, registration_nonce, nonce_signature);
    return 0;
}
