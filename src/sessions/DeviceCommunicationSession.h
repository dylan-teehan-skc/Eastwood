//
// Created by Josh Sloggett on 21/05/2025.
//

#ifndef DEVICECOMMUNICATIONSESSION_H
#define DEVICECOMMUNICATIONSESSION_H

#include <memory>
#include "../key_exchange/DoubleRatchet.h"
#include "../key_exchange/x3dh.h"
#include <sodium.h>
#include <memory>

class DeviceCommunicationSession {
public:
    DeviceCommunicationSession();
    virtual ~DeviceCommunicationSession();
    virtual const unsigned char* getSharedSecret() const = 0;
    virtual DoubleRatchet* getRatchet() = 0;
    unsigned char* getDeviceSessionId();

    void message_send(unsigned char* message);
    void message_receive(DeviceMessage message);
protected:
    unsigned char* device_session_id;
    const unsigned char *device_id;
    std::unique_ptr<DoubleRatchet> ratchet;
    unsigned char* shared_secret;
};

class DeviceSendingCommunicationSession: public DeviceCommunicationSession {
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
    
    ~DeviceSendingCommunicationSession() override;
    const unsigned char* getSharedSecret() const override;
    DoubleRatchet* getRatchet() override;
};

class DeviceReceivingCommunicationSession: public DeviceCommunicationSession {
public:
    DeviceReceivingCommunicationSession(
        const unsigned char* initiator_device_key_public,
        const unsigned char* initiator_ephemeral_key_public,
        const unsigned char* device_key_public,
        const unsigned char* device_key_private,
        const unsigned char* signed_prekey_public,
        const unsigned char* signed_prekey_private,
        const unsigned char* onetime_prekey_private);
    
    ~DeviceReceivingCommunicationSession() override;
    const unsigned char* getSharedSecret() const override;
    DoubleRatchet* getRatchet() override;
};

#endif //COMMUNICATIONSESSION_H
