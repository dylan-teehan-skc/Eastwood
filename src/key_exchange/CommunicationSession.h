//
// Created by Josh Sloggett on 21/05/2025.
//

#ifndef COMMUNICATIONSESSION_H
#define COMMUNICATIONSESSION_H
#include "DoubleRatchet.h"
#include "x3dh.h"
#include <sodium.h>
#include <memory>

class SendingCommunicationSession {
private:
    unsigned char* shared_secret;
    std::unique_ptr<DoubleRatchet> ratchet;

public:
    SendingCommunicationSession(
        const unsigned char* identity_key_public,
        const unsigned char* identity_key_private,
        const unsigned char* ephemeral_key_public,
        const unsigned char* ephemeral_key_private,
        const unsigned char* recipient_identity_key_public,
        const unsigned char* recipient_signed_prekey_public,
        const unsigned char* recipient_onetime_prekey_public,
        const unsigned char* recipient_signed_prekey_signature,
        const unsigned char* recipient_ed25519_identity_key_public);
    
    ~SendingCommunicationSession();
    
    const unsigned char* getSharedSecret() const;
    
    DoubleRatchet* getRatchet();
};

class ReceivingCommunicationSession {
private:
    unsigned char* shared_secret;
    std::unique_ptr<DoubleRatchet> ratchet;

public:
    ReceivingCommunicationSession(
        const unsigned char* initiator_identity_key_public,
        const unsigned char* initiator_ephemeral_key_public,
        const unsigned char* identity_key_public,
        const unsigned char* identity_key_private,
        const unsigned char* signed_prekey_public,
        const unsigned char* signed_prekey_private,
        const unsigned char* onetime_prekey_public,
        const unsigned char* onetime_prekey_private);
    
    ~ReceivingCommunicationSession();
    
    const unsigned char* getSharedSecret() const;
    
    DoubleRatchet* getRatchet();
};

#endif //COMMUNICATIONSESSION_H
