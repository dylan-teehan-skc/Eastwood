#include <cstdio>
#include <iostream>
#include <string>
#include <sodium.h>
#include <memory>
#include "src/algorithms/algorithms.h"

#include "../../algorithms/constants.h"
#include "src/auth/set_up_client.h"
#include "src/endpoints/endpoints.h"
#include "src/sql/queries.h"
#include "src/utils/ConversionUtils.h"


void register_user(const std::string &username, const std::unique_ptr<const std::string> &master_password,
                  const bool DEBUG_REFRESH_TABLES = false) {
    qDebug() << "Registering user";

    set_up_client_for_user(username, std::move(master_password), DEBUG_REFRESH_TABLES);

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
}
