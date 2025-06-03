#include "register_device.h"
#include <sodium.h>

#include <string>

#include "src/sql/queries.h"
#include "src/algorithms/algorithms.h"
#include "src/algorithms/constants.h"
#include "src/endpoints/endpoints.h"
#include "src/utils/ConversionUtils.h"
#include "src/database/database.h"

void add_trusted_device(unsigned char pk_new_device[crypto_sign_PUBLICKEYBYTES], const std::string &device_name) {
    qDebug() << "Registering device";
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }

    const auto [pk_identity,sk_identity] = get_decrypted_keypair("identity");

    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char pk_signature[crypto_sign_BYTES];
    crypto_sign_detached(pk_signature, nullptr, pk_new_device, crypto_sign_PUBLICKEYBYTES, sk_identity->data());

    try {
        post_register_device(q_byte_array_to_chars(pk_identity), pk_new_device, pk_signature, device_name);
    } catch (const std::exception& e) {
        qDebug() << "Failed to register device:" << e.what();
        throw std::runtime_error("Failed to register device with server");
    }

    post_new_keybundles(
        get_decrypted_keypair("device"),
        generate_signed_prekey(),
        generate_onetime_keys(50)
        );
}

void register_first_device() {
    qDebug() << "Registering first device";
    unsigned char pk_device[crypto_sign_PUBLICKEYBYTES];
    const auto sk_device = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pk_device, sk_device->data());

    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

    const auto esk_device = encrypt_secret_key(sk_device, nonce);
    save_encrypted_keypair("device", pk_device, esk_device, nonce);
    add_trusted_device(pk_device, "Primary Device");
}