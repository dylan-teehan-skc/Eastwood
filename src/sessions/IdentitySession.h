//
// Created by Josh Sloggett on 28/05/2025.
//

#ifndef EASTWOOD_IDENTITY_SESSION_H
#define EASTWOOD_IDENTITY_SESSION_H

#include <vector>
#include <map>
#include <memory>
#include <array>
#include "IdentitySessionId.h"
#include "KeyBundle.h"
#include "src/key_exchange/NewRatchet.h"

class IdentitySession {
private:
    unsigned char* identity_session_id[32];
    std::map<unsigned char*, std::unique_ptr<NewRatchet>> ratchets;

public:
    IdentitySession(std::vector<KeyBundle*> const &keys, const unsigned char* identity_session_id_in);
    ~IdentitySession();

    void updateFromBundles(std::vector<KeyBundle*> bundles);
    void create_ratchet_if_needed(const unsigned char* device_id_one, const unsigned char* device_id_two, KeyBundle* bundle);
    std::vector<std::tuple<IdentitySessionId, std::unique_ptr<DeviceMessage>>> send_message(const unsigned char* message, size_t message_len);
    std::vector<unsigned char> receive_message(DeviceMessage *message);
};

#endif //EASTWOOD_IDENTITY_SESSION_H
