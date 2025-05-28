#include "session_token_manager.h"

SessionTokenManager& SessionTokenManager::instance() {
    static SessionTokenManager instance;
    return instance;
}

void SessionTokenManager::setToken(const std::string& token) {
    token_ = token;
    has_token_ = true;
}

const std::string& SessionTokenManager::getToken() const {
    if (!has_token_) {
        throw std::runtime_error("Session token not set");
    }
    return token_;
}

bool SessionTokenManager::hasToken() const {
    return has_token_;
} 