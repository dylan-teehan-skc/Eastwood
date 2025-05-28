#include <cstdio>
#include <iostream>
#include <string>
#include <sodium.h>
#include <memory>
#include "src/algorithms/algorithms.h"

#include "../../algorithms/constants.h"
#include "src/endpoints/endpoints.h"
#include "src/sql/queries.h"
#include "src/utils/ConversionUtils.h"


int register_user(const std::string &username, const std::unique_ptr<const std::string> &master_password) {
    qDebug() << "Registering user";
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium initialization failed\n");
        return 1;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);

    auto master_key = derive_master_key(std::move(master_password), salt);

    auto kek = SecureMemoryBuffer::create(SYM_KEY_LEN);
    crypto_secretbox_keygen(kek->data());

    unsigned char nonce_kek[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce_kek, sizeof(nonce_kek));

    const auto encrypted_kek = encrypt_kek(kek, nonce_kek, master_key);
    KekManager::instance().setKEK(std::move(kek));

    save_encrypted_key("kek", encrypted_kek, nonce_kek);
    // TODO: post_store_kek(kek, nonce_kek);

    unsigned char pk_identity[crypto_sign_PUBLICKEYBYTES];

    const auto sk_identity = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk_identity, sk_identity->data());

    unsigned char nonce_sk[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce_sk, CHA_CHA_NONCE_LEN);

    const auto encrypted_sk = encrypt_secret_key(sk_identity, nonce_sk);

    save_encrypted_keypair("identity", pk_identity, encrypted_sk, nonce_sk);

    unsigned char registration_nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(registration_nonce, sizeof(registration_nonce));

    unsigned char nonce_signature[crypto_sign_BYTES];
    crypto_sign_detached(nonce_signature, nullptr, registration_nonce, CHA_CHA_NONCE_LEN, sk_identity->data());

    post_register_user(username, pk_identity, registration_nonce, nonce_signature);
    return 0;
}
