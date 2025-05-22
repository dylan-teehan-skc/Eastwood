//
// Created by Josh Sloggett on 20/05/2025.
//

#ifndef X3DH_H
#define X3DH_H

#include <sodium.h>

static constexpr size_t KEY_LEN = crypto_scalarmult_BYTES;

unsigned char* x3dh_initiator(
    const unsigned char* my_identity_key_public,
    const unsigned char* my_identity_key_private,
    const unsigned char* my_ephemeral_key_public,
    const unsigned char* my_ephemeral_key_private,
    const unsigned char* recipient_identity_key_public,
    const unsigned char* recipient_signed_prekey_public,
    const unsigned char* recipient_onetime_prekey_public,
    const unsigned char* recipient_signed_prekey_signature,
    const unsigned char* recipient_ed25519_identity_key_public);

unsigned char* x3dh_responder(
    const unsigned char* initiator_identity_key_public,
    const unsigned char* initiator_ephemeral_key_public,
    const unsigned char* my_identity_key_public,
    const unsigned char* my_identity_key_private,
    const unsigned char* my_signed_prekey_public,
    const unsigned char* my_signed_prekey_private,
    const unsigned char* my_onetime_prekey_public,
    const unsigned char* my_onetime_prekey_private);

#endif //X3DH_H
