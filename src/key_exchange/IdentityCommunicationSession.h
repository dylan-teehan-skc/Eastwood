//
// Created by Josh Sloggett on 22/05/2025.
//

#ifndef IDENTITYCOMMUNICATIONSESSION_H
#define IDENTITYCOMMUNICATIONSESSION_H
#include <vector>
#include "DeviceCommunicationSession.h"

struct keyBundle {
    bool isSending;
    unsigned char* device_key_public[crypto_box_PUBLICKEYBYTES];
    unsigned char* device_key_private[crypto_box_SECRETKEYBYTES];

    unsigned char* ed25519_device_key_public[crypto_sign_PUBLICKEYBYTES];
    unsigned char* ed25519_device_key_private[crypto_sign_SECRETKEYBYTES];

    unsigned char* ephemeral_key_public[crypto_box_PUBLICKEYBYTES];
    unsigned char* ephemeral_key_private[crypto_box_SECRETKEYBYTES];

    unsigned char* signed_prekey_public[crypto_box_PUBLICKEYBYTES];
    unsigned char* signed_prekey_private[crypto_box_SECRETKEYBYTES];
    unsigned char* signed_prekey_signature[crypto_sign_BYTES];

    unsigned char* onetime_prekey_public[crypto_box_PUBLICKEYBYTES];
    unsigned char* onetime_prekey_private[crypto_box_SECRETKEYBYTES];
};

class IdentityCommunicationSession {
    // identity session key = two identity keys together in alphabetical order hashed
    // this is our out of band code to verify
public:
    IdentityCommunicationSession(keyBundle myBundle, std::vector<keyBundle>, unsigned char* , unsigned char*);
    // use vector of keybundles to establish per device sessions
    // ensure to make sure the device session does not already exist
    // device session id of two device ids in alphabetical order hashed
    ~IdentityCommunicationSession();
private:
    keyBundle myBundle;
    unsigned char* identity_session_id;
    std::map<unsigned char*, DeviceCommunicationSession*> device_sessions;

    void createSessionFromKeyBundle(keyBundle);
    void updateSessionsFromKeyBundles(std::vector<keyBundle>);
};



#endif //IDENTITYCOMMUNICATIONSESSION_H
