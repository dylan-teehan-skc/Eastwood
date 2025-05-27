//
// Created by Josh Sloggett on 27/05/2025.
//

#include "src/key_exchange/utils.h"
#include "SessionManager.h"

void SessionManager::import_key_bundles(keyBundleRequest request) {
    size_t identity_session_key_len = sizeof(request.my_identity_public) + sizeof(request.their_identity_public);
    unsigned char* identity_session_id = concat_ordered(request.my_identity_public, crypto_box_PUBLICKEYBYTES, request.their_identity_public, crypto_box_PUBLICKEYBYTES, identity_session_key_len);

    if (!identity_sessions[identity_session_id]) {
        keyBundle my_key_bundle;
        // TODO:: fetch device keys from db
        identity_sessions[identity_session_id] = new IdentityCommunicationSession(my_key_bundle, request.key_bundles, request.my_identity_public, request.their_identity_public);
    } else {
        identity_sessions[identity_session_id]->updateSessionsFromKeyBundles(request.key_bundles);
    }
}

