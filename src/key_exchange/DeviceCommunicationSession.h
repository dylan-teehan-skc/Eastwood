//
// Created by Josh Sloggett on 21/05/2025.
//

#ifndef COMMUNICATIONSESSION_H
#define COMMUNICATIONSESSION_H
#include "DoubleRatchet.h"
#include <sodium.h>
#include <memory>
#include <vector>
#include <string>
#include <cereal/cereal.hpp>
#include <cereal/archives/json.hpp>
#include <fstream>

class DeviceCommunicationSession {
public:
    DeviceCommunicationSession();
    virtual ~DeviceCommunicationSession() = default;
    virtual const std::vector<uint8_t>& getSharedSecret() const = 0;
    virtual DoubleRatchet* getRatchet() = 0;
    const std::vector<uint8_t>& getDeviceSessionId() const;

    // Save this session to a file
    void save(const std::string& filename) const {
        std::ofstream ofs(filename);
        cereal::JSONOutputArchive oarchive(ofs);
        oarchive(*this);
    }

    // Load this session from a file
    void load(const std::string& filename) {
        std::ifstream ifs(filename);
        cereal::JSONInputArchive iarchive(ifs);
        iarchive(*this);
    }

    template<class Archive>
    void serialize(Archive& ar) {
        ar(device_session_id, ratchet, shared_secret);
    }
protected:
    std::vector<uint8_t> device_session_id;
    std::unique_ptr<DoubleRatchet> ratchet;
    std::vector<uint8_t> shared_secret;
};

class DeviceSendingCommunicationSession: public DeviceCommunicationSession {
public:
    DeviceSendingCommunicationSession() = default;
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
    
    ~DeviceSendingCommunicationSession() override = default;
    const std::vector<uint8_t>& getSharedSecret() const override;
    DoubleRatchet* getRatchet() override;

    template<class Archive>
    void serialize(Archive& ar) {
        ar(cereal::base_class<DeviceCommunicationSession>(this));
    }
};

class DeviceReceivingCommunicationSession: public DeviceCommunicationSession {
public:
    DeviceReceivingCommunicationSession() = default;
    DeviceReceivingCommunicationSession(
        const unsigned char* initiator_device_key_public,
        const unsigned char* initiator_ephemeral_key_public,
        const unsigned char* device_key_public,
        const unsigned char* device_key_private,
        const unsigned char* signed_prekey_public,
        const unsigned char* signed_prekey_private,
        const unsigned char* onetime_prekey_private);
    
    ~DeviceReceivingCommunicationSession() override = default;
    const std::vector<uint8_t>& getSharedSecret() const override;
    DoubleRatchet* getRatchet() override;

    template<class Archive>
    void serialize(Archive& ar) {
        ar(cereal::base_class<DeviceCommunicationSession>(this));
    }
};

#endif //COMMUNICATIONSESSION_H
