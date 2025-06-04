#include "x3dh.h"
#include <sodium.h>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <optional>

#include "src/sql/queries.h"

static std::string bin2hex(const std::array<unsigned char, 32>bin, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bin[i]);
    return oss.str();
}

std::array<unsigned char, 32> x3dh_initiator(
    std::unique_ptr<SecureMemoryBuffer> my_identity_key_private,
    std::shared_ptr<SecureMemoryBuffer> my_ephemeral_key_private,
    const std::array<unsigned char, 32> recipient_identity_key_public,
    const std::array<unsigned char, 32> recipient_signed_prekey_public,
    const std::optional<std::array<unsigned char, 32>> recipient_onetime_prekey_public
) {
    constexpr size_t KEY_LEN = crypto_scalarmult_BYTES;

    unsigned char dh1[KEY_LEN], dh2[KEY_LEN], dh3[KEY_LEN], dh4[KEY_LEN];

    // DH1: my_identity_private * their_signed_prekey_public
    unsigned char my_id_x25519_sk[KEY_LEN];
    if (crypto_sign_ed25519_sk_to_curve25519(my_id_x25519_sk, my_identity_key_private->data()) != 0)
        throw std::runtime_error("Failed to convert my identity private key to X25519");
    
    if (crypto_scalarmult(dh1, my_id_x25519_sk, recipient_signed_prekey_public.data()) != 0)
        throw std::runtime_error("DH1 failed");

    // DH2: my_ephemeral_private * their_identity_public
    unsigned char their_id_x25519_pk[KEY_LEN];
    if (crypto_sign_ed25519_pk_to_curve25519(their_id_x25519_pk, recipient_identity_key_public.data()) != 0)
        throw std::runtime_error("Failed to convert recipient identity public key to X25519");
    
    if (crypto_scalarmult(dh2, my_ephemeral_key_private->data(), their_id_x25519_pk) != 0)
        throw std::runtime_error("DH2 failed");

    // DH3: my_ephemeral_private * their_signed_prekey_public
    if (crypto_scalarmult(dh3, my_ephemeral_key_private->data(), recipient_signed_prekey_public.data()) != 0)
        throw std::runtime_error("DH3 failed");

    // DH4: my_ephemeral_private * their_onetime_prekey_public
    if (recipient_onetime_prekey_public.has_value()) {
        if (crypto_scalarmult(dh4, my_ephemeral_key_private->data(), recipient_onetime_prekey_public.value().data()) != 0)
            throw std::runtime_error("DH4 failed");
    } else {
        memset(dh4, 0, KEY_LEN);
    }

    unsigned char ikm[KEY_LEN * 4];
    memcpy(ikm, dh1, KEY_LEN);
    memcpy(ikm + KEY_LEN, dh2, KEY_LEN);
    memcpy(ikm + 2 * KEY_LEN, dh3, KEY_LEN);
    memcpy(ikm + 3 * KEY_LEN, dh4, KEY_LEN);

    std::array<unsigned char, 32> shared_secret;
    crypto_generichash(shared_secret.data(), KEY_LEN, ikm, sizeof(ikm), nullptr, 0);

    return shared_secret;
}

std::array<unsigned char, 32> x3dh_responder(
    const std::array<unsigned char, 32> initiator_identity_key_public,
    const std::array<unsigned char, 32> initiator_ephemeral_key_public,
    std::unique_ptr<SecureMemoryBuffer> my_identity_key_private,
    std::unique_ptr<SecureMemoryBuffer> my_signed_prekey_private,
    std::optional<std::unique_ptr<SecureMemoryBuffer>> my_onetime_prekey_private
    ) {
    constexpr size_t KEY_LEN = crypto_scalarmult_BYTES;

    unsigned char dh1[KEY_LEN], dh2[KEY_LEN], dh3[KEY_LEN], dh4[KEY_LEN];

    // DH1: my_signed_prekey_private * their_identity_public
    unsigned char their_id_x25519_pk[KEY_LEN];
    if (crypto_sign_ed25519_pk_to_curve25519(their_id_x25519_pk, initiator_identity_key_public.data()) != 0)
        throw std::runtime_error("Failed to convert initiator identity public key to X25519");
    
    if (crypto_scalarmult(dh1, my_signed_prekey_private->data(), their_id_x25519_pk) != 0)
        throw std::runtime_error("DH1 failed");

    // DH2: my_identity_private * their_ephemeral_public
    unsigned char my_id_x25519_sk[KEY_LEN];
    if (crypto_sign_ed25519_sk_to_curve25519(my_id_x25519_sk, my_identity_key_private->data()) != 0)
        throw std::runtime_error("Failed to convert my identity private key to X25519");
    
    if (crypto_scalarmult(dh2, my_id_x25519_sk, initiator_ephemeral_key_public.data()) != 0)
        throw std::runtime_error("DH2 failed");

    // DH3: my_signed_prekey_private * their_ephemeral_public
    if (crypto_scalarmult(dh3, my_signed_prekey_private->data(), initiator_ephemeral_key_public.data()) != 0)
        throw std::runtime_error("DH3 failed");

    // DH4: my_onetime_prekey_private * their_ephemeral_public
    if (my_onetime_prekey_private.has_value()) {
        if (crypto_scalarmult(dh4, my_onetime_prekey_private.value()->data(), initiator_ephemeral_key_public.data()) != 0)
            throw std::runtime_error("DH4 failed");
    } else {
        memset(dh4, 0, KEY_LEN);
    }

    unsigned char ikm[KEY_LEN * 4];
    memcpy(ikm, dh1, KEY_LEN);
    memcpy(ikm + KEY_LEN, dh2, KEY_LEN);
    memcpy(ikm + 2 * KEY_LEN, dh3, KEY_LEN);
    memcpy(ikm + 3 * KEY_LEN, dh4, KEY_LEN);

    std::array<unsigned char, 32> shared_secret;
    crypto_generichash(shared_secret.data(), KEY_LEN, ikm, sizeof(ikm), nullptr, 0);

    return shared_secret;
}
