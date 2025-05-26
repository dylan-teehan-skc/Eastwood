//
// Created by Josh Sloggett on 22/05/2025.
//
#include "IdentityCommunicationSession.h"
#include "utils.h"

IdentityCommunicationSession::IdentityCommunicationSession(const keyBundle &myBundle, const std::vector<keyBundle> &key_bundles, const unsigned char* public_identity_key_1, const unsigned char* public_identity_key_2)
    : myBundle(myBundle) {
    // out of band verification between users
    size_t identity_session_key_len = sizeof(public_identity_key_1) + sizeof(public_identity_key_2);
    identity_session_id = concat_ordered(public_identity_key_1, crypto_box_PUBLICKEYBYTES, public_identity_key_2, crypto_box_PUBLICKEYBYTES, identity_session_key_len);

    updateSessionsFromKeyBundles(key_bundles);
}

void IdentityCommunicationSession::updateSessionsFromKeyBundles(const std::vector<keyBundle> &key_bundles) {
    // create session for key bundle
    for (const auto & key_bundle : key_bundles) {
        createSessionFromKeyBundle(key_bundle);
    }
}

void IdentityCommunicationSession::createSessionFromKeyBundle(const keyBundle &key_bundle) {
    //1. compute device_session_id
    size_t identity_session_key_len = sizeof(myBundle.device_key_public) + sizeof(key_bundle.device_key_public);
    unsigned char* device_session_id_new = concat_ordered(*myBundle.device_key_public, crypto_box_PUBLICKEYBYTES, *key_bundle.device_key_public, crypto_box_PUBLICKEYBYTES, identity_session_key_len);

    //2. verify if device_session_id doesnt exist already
    if (!device_sessions[device_session_id_new]) {
        //3. create new device session
        if (key_bundle.isSending) {
            device_sessions[device_session_id_new] = new DeviceSendingCommunicationSession(
            *key_bundle.device_key_public,
            *key_bundle.device_key_private,
            *key_bundle.ephemeral_key_public,
            *key_bundle.ephemeral_key_private,
            *myBundle.device_key_public,
            *myBundle.signed_prekey_public,
            *myBundle.onetime_prekey_public,
            *myBundle.signed_prekey_signature,
            *myBundle.ed25519_device_key_public
            );
        } else {
            device_sessions[device_session_id_new] = new DeviceReceivingCommunicationSession(
            *key_bundle.device_key_public,
            *key_bundle.ephemeral_key_public,
            *myBundle.device_key_public,
            *myBundle.device_key_private,
            *myBundle.signed_prekey_public,
            *myBundle.signed_prekey_private,
            *myBundle.onetime_prekey_private
            );
        }
    }
}

IdentityCommunicationSession::~IdentityCommunicationSession() {
    // Clean up all device sessions
    for (auto& pair : device_sessions) {
        delete pair.second;
    }
    device_sessions.clear();
    
    // Clean up identity session ID
    if (identity_session_id) {
        delete[] identity_session_id;
    }
}

