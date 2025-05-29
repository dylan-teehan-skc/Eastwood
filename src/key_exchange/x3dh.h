//
// Created by Josh Sloggett on 20/05/2025.
//

#ifndef X3DH_H
#define X3DH_H

#include <memory>
#include <sodium.h>

#include "src/keys/secure_memory_buffer.h"

static constexpr size_t KEY_LEN = crypto_scalarmult_BYTES;

unsigned char* x3dh_initiator(
    std::unique_ptr<SecureMemoryBuffer> my_identity_key_private,
    std::shared_ptr<SecureMemoryBuffer> my_ephemeral_key_private,
    const unsigned char* recipient_identity_key_public,
    const unsigned char* recipient_signed_prekey_public,
    const unsigned char* recipient_onetime_prekey_public
    );

unsigned char* x3dh_responder(
    const unsigned char* initiator_identity_key_public,
    const unsigned char* initiator_ephemeral_key_public,
    std::unique_ptr<SecureMemoryBuffer> my_identity_key_private,
    std::unique_ptr<SecureMemoryBuffer> my_signed_prekey_private,
    std::unique_ptr<SecureMemoryBuffer> my_onetime_prekey_private);

#endif //X3DH_H
