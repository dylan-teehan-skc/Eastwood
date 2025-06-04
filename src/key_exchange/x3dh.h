//
// Created by Josh Sloggett on 20/05/2025.
//

#ifndef X3DH_H
#define X3DH_H

#include <memory>
#include <optional>
#include <sodium.h>

#include "src/keys/secure_memory_buffer.h"

static constexpr size_t KEY_LEN = crypto_scalarmult_BYTES;

std::array<unsigned char, 32> x3dh_initiator(
    const std::unique_ptr<SecureMemoryBuffer> my_identity_key_private,
    const std::shared_ptr<SecureMemoryBuffer> my_ephemeral_key_private,
    const std::array<unsigned char, 32> recipient_identity_key_public,
    const std::array<unsigned char, 32> recipient_signed_prekey_public,
    const std::optional<std::array<unsigned char, 32>> recipient_onetime_prekey_public
    );

std::array<unsigned char, 32> x3dh_responder(
    const std::array<unsigned char, 32> initiator_identity_key_public,
    const std::array<unsigned char, 32> initiator_ephemeral_key_public,
    const std::unique_ptr<SecureMemoryBuffer> my_identity_key_private,
    const std::unique_ptr<SecureMemoryBuffer> my_signed_prekey_private,
    const std::optional<std::unique_ptr<SecureMemoryBuffer>> my_onetime_prekey_private);

#endif //X3DH_H
