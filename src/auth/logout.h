
#ifndef LOGOUT_H
#define LOGOUT_H
#include "src/database/database.h"
#include "src/keys/kek_manager.h"
#include "src/keys/session_token_manager.h"

inline void logout() {
    Database::get().closeDatabase();
    KekManager::instance().unload();
    SessionTokenManager::instance().clearToken();
}


#endif //LOGOUT_H
