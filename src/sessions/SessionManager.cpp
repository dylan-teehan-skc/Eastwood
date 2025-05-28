//
// Created by Josh Sloggett on 27/05/2025.
//

#include "src/key_exchange/utils.h"
#include "SessionManager.h"
#include "src/sql/queries.h"

SessionManager::SessionManager() {}

SessionManager::~SessionManager() {
    for (auto& pair : identity_sessions) {
        delete pair.second;
    }
}

void SessionManager::import_key_bundles(keyBundleRequest request) {
    size_t identity_session_key_len = sizeof(request.my_identity_public) + sizeof(request.their_identity_public);
    unsigned char* identity_session_id = concat_ordered(request.my_identity_public, crypto_box_PUBLICKEYBYTES, request.their_identity_public, crypto_box_PUBLICKEYBYTES, identity_session_key_len);

    if (!identity_sessions[identity_session_id]) {
        keyBundle my_key_bundle;
        my_key_bundle.isSending = true;  // We are the sender in this case
        
        // Fetch device keys from database
        std::tuple<QByteArray, QByteArray, QByteArray> device_keypair = get_keypair("device");
        QByteArray device_public = std::get<0>(device_keypair);
        QByteArray device_private = std::get<1>(device_keypair);
        
        // Allocate and copy device keys
        my_key_bundle.device_key_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
        my_key_bundle.device_key_private = new unsigned char[crypto_box_SECRETKEYBYTES];
        memcpy(my_key_bundle.device_key_public, device_public.data(), crypto_box_PUBLICKEYBYTES);
        memcpy(my_key_bundle.device_key_private, device_private.data(), crypto_box_SECRETKEYBYTES);
        
        // Generate ephemeral keys
        my_key_bundle.ephemeral_key_public = new unsigned char[crypto_box_PUBLICKEYBYTES];
        my_key_bundle.ephemeral_key_private = new unsigned char[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(my_key_bundle.ephemeral_key_public, my_key_bundle.ephemeral_key_private);
        
        // Initialize other keys to nullptr since we don't need them for sending
        my_key_bundle.signed_prekey_public = nullptr;
        my_key_bundle.signed_prekey_private = nullptr;
        my_key_bundle.signed_prekey_signature = nullptr;
        my_key_bundle.onetime_prekey_public = nullptr;
        my_key_bundle.onetime_prekey_private = nullptr;
        my_key_bundle.ed25519_device_key_public = nullptr;
        my_key_bundle.ed25519_device_key_private = nullptr;
        
        identity_sessions[identity_session_id] = new IdentityCommunicationSession(my_key_bundle, request.key_bundles, request.my_identity_public, request.their_identity_public);
    } else {
        identity_sessions[identity_session_id]->updateSessionsFromKeyBundles(request.key_bundles);
    }
}

void SessionManager::routeToIdentity(DeviceMessage message, unsigned char* other_identity) {
    std::tuple<QByteArray, QByteArray, QByteArray> keypair = get_keypair("identity");
    QByteArray identity_key_ba = std::get<0>(keypair);
    unsigned char* identity_key = new unsigned char[identity_key_ba.size()];
    memcpy(identity_key, identity_key_ba.data(), identity_key_ba.size());

    size_t identity_session_key_len = crypto_box_PUBLICKEYBYTES * 2;
    unsigned char* identity_session_id = new unsigned char[identity_session_key_len];
    memcpy(identity_session_id, identity_key, crypto_box_PUBLICKEYBYTES);
    memcpy(identity_session_id + crypto_box_PUBLICKEYBYTES, other_identity, crypto_box_PUBLICKEYBYTES);

    auto it = identity_sessions.find(identity_session_id);
    if (it == identity_sessions.end()) {
        delete[] identity_key;
        delete[] identity_session_id;
        throw std::runtime_error("Identity session does not exist");
    }

    it->second->message_receive(message);
    delete[] identity_key;
    delete[] identity_session_id;
}

