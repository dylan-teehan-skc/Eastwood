//
// Created by Josh Sloggett on 27/05/2025.
//

#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H
#include "IdentityCommunicationSession.h"

struct keyBundleRequest {
    unsigned char* my_identity_public;
    unsigned char* their_identity_public;
    std::vector<keyBundle> key_bundles;
};


class SessionManager {
    public:
    SessionManager();
    ~SessionManager();

    void import_key_bundles(keyBundleRequest request);
private:
    std::map<unsigned char*, IdentityCommunicationSession*> identity_sessions;
};



#endif //SESSIONMANAGER_H
