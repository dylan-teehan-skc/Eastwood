#include "register_device.h"
#include <sodium.h>

#include <string>

#include "src/algorithms/algorithms.h"
#include "src/algorithms/constants.h"
#include "src/endpoints/endpoints.h"
#include "src/keys/kek_manager.h"

void load_private_key(unsigned char key_out[crypto_sign_SECRETKEYBYTES], const char *keyName) {
    const unsigned char *kek = KEKManager::get_kek();
    const unsigned char *encrypted_sk, *nonce; // = db.get_private_key(keyName);
    decrypt_secret_key(key_out, encrypted_sk, nonce, kek);
};

int register_device(unsigned char pk_new_device[crypto_sign_PUBLICKEYBYTES]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Libsodium initialization failed\n");
        return 1;
    }

    unsigned char sk_identity[crypto_sign_SECRETKEYBYTES];
    load_private_key(sk_identity, "Identity");

    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char pk_signature[crypto_sign_BYTES];
    crypto_sign_detached(pk_new_device, nullptr, nonce, NONCE_LEN, sk_identity);

    unsigned char pk_id[crypto_sign_PUBLICKEYBYTES];

    post_register_device(pk_id, pk_new_device, pk_signature);
    return 0;
}
