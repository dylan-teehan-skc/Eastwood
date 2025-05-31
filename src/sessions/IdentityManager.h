//
// Created by Josh Sloggett on 28/05/2025.
//

#ifndef EASTWOOD_IDENTITY_MANAGER_H
#define EASTWOOD_IDENTITY_MANAGER_H

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <tuple>
#include "IdentitySessionId.h"
#include "IdentitySession.h"

class IdentityManager {
private:
    std::map<IdentitySessionId, std::unique_ptr<IdentitySession>> _sessions;
    static IdentityManager* _instance;

public:
    static IdentityManager& getInstance() {
        static IdentityManager instance;
        return instance;
    }
    void update_or_create_identity_sessions(std::vector<KeyBundle*> bundles, std::string username_one, std::string username_two);
    void update_or_create_identity_sessions(std::vector<std::tuple<IdentitySessionId, KeyBundle*>> bundles_with_ids);

    void receive_messages(std::vector<std::tuple<IdentitySessionId, DeviceMessage*>> messages_with_ids);
    std::vector<std::tuple<IdentitySessionId, std::unique_ptr<DeviceMessage>>> send_to_user(std::string username, unsigned char* msg);
    void print_all_session_ids();
};

#endif //EASTWOOD_IDENTITY_MANAGER_H
