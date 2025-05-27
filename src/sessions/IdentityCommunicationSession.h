//
// Created by Josh Sloggett on 22/05/2025.
//

#ifndef IDENTITYCOMMUNICATIONSESSION_H
#define IDENTITYCOMMUNICATIONSESSION_H

#include <vector>
#include <map>
#include "DeviceCommunicationSession.h"
#include "../key_exchange/DoubleRatchet.h"
#include "../key_exchange/utils.h"

struct keyBundle {
    bool isSending;
    unsigned char* device_key_public;
    unsigned char* device_key_private;

    unsigned char* ed25519_device_key_public;
    unsigned char* ed25519_device_key_private;

    unsigned char* ephemeral_key_public;
    unsigned char* ephemeral_key_private;

    unsigned char* signed_prekey_public;
    unsigned char* signed_prekey_private;
    unsigned char* signed_prekey_signature;

    unsigned char* onetime_prekey_public;
    unsigned char* onetime_prekey_private;
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

    void message_send(unsigned char* message);
    void message_receive(DeviceMessage message);

    // Public methods for testing
    const std::map<unsigned char*, DeviceCommunicationSession*>& getDeviceSessions() const { return device_sessions; }
    void updateSessionsFromKeyBundles(std::vector<keyBundle> key_bundles);

private:
    keyBundle myBundle;
    unsigned char* identity_session_id;
    std::map<unsigned char*, DeviceCommunicationSession*> device_sessions;

    void createSessionFromKeyBundle(keyBundle);
};

#endif //IDENTITYCOMMUNICATIONSESSION_H
