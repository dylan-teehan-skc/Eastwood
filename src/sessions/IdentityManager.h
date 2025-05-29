//
// Created by Josh Sloggett on 28/05/2025.
//

#ifndef IDENTITYMANAGER_H
#define IDENTITYMANAGER_H

#include <map>
#include <memory>
#include "IdentitySession.h"

class IdentityManager {
public:
    static IdentityManager& getInstance() {
        static IdentityManager instance;
        return instance;
    }

    void update_or_create_identity_sessions(std::vector<KeyBundle*> bundles, std::string username_one, std::string username_two);
    void update_or_create_identity_sessions(std::vector<KeyBundle*> bundles, unsigned char* identity_session_id);

private:
    IdentityManager() = default;
    ~IdentityManager() = default;
    IdentityManager(const IdentityManager&) = delete;
    IdentityManager& operator=(const IdentityManager&) = delete;

    std::map<unsigned char*, std::unique_ptr<IdentitySession>> _sessions;
};

#endif //IDENTITYMANAGER_H
