//
// Created by Josh Sloggett on 21/05/2025.
//

#ifndef COMMUNICATIONSESSION_H
#define COMMUNICATIONSESSION_H
#include "DoubleRatchet.h"
#include "x3dh.h"
#include <sodium.h>
#include <memory>

class DeviceSendingCommunicationSession {
private:
    unsigned char* shared_secret;
    std::unique_ptr<DoubleRatchet> ratchet;

public:
    DeviceSendingCommunicationSession(
        const unsigned char* device_key_public,
        const unsigned char* device_key_private,
        const unsigned char* ephemeral_key_public,
        const unsigned char* ephemeral_key_private,
        const unsigned char* recipient_device_key_public,
        const unsigned char* recipient_signed_prekey_public,
        const unsigned char* recipient_onetime_prekey_public,
        const unsigned char* recipient_signed_prekey_signature,
        const unsigned char* recipient_ed25519_device_key_public);
    
    ~DeviceSendingCommunicationSession();
    
    const unsigned char* getSharedSecret() const;
    
    DoubleRatchet* getRatchet();
};

class DeviceReceivingCommunicationSession {
private:
    unsigned char* shared_secret;
    std::unique_ptr<DoubleRatchet> ratchet;

public:
    DeviceReceivingCommunicationSession(
        const unsigned char* initiator_device_key_public,
        const unsigned char* initiator_ephemeral_key_public,
        const unsigned char* device_key_public,
        const unsigned char* device_key_private,
        const unsigned char* signed_prekey_public,
        const unsigned char* signed_prekey_private,
        const unsigned char* onetime_prekey_public,
        const unsigned char* onetime_prekey_private);
    
    ~DeviceReceivingCommunicationSession();
    
    const unsigned char* getSharedSecret() const;
    
    DoubleRatchet* getRatchet();
};

#endif //COMMUNICATIONSESSION_H
