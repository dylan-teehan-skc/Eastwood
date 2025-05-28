#include "register_device.h"
#include <sodium.h>

#include <string>

#include "src/sql/queries.h"
#include "src/algorithms/algorithms.h"
#include "src/algorithms/constants.h"
#include "src/endpoints/endpoints.h"
#include "src/utils/ConversionUtils.h"

void register_device(unsigned char pk_new_device[crypto_sign_PUBLICKEYBYTES]) {
    qDebug() << "Registering device";
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }

    auto pk_identity = get_public_key("identity");
    auto sk_identity = get_decrypted_sk("identity");

    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char pk_signature[crypto_sign_BYTES];
    crypto_sign_detached(pk_signature, nullptr, pk_new_device, crypto_sign_PUBLICKEYBYTES, sk_identity->data());

    post_register_device(q_byte_array_to_chars(pk_identity), pk_new_device, pk_signature);
}

void register_first_device() {
    qDebug() << "Registering first device";
    unsigned char pk_device[crypto_sign_PUBLICKEYBYTES];
    const auto sk_device = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk_device, sk_device->data());

    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, CHA_CHA_NONCE_LEN);
    register_device(pk_device);
}
