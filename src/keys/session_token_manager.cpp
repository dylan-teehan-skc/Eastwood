#include "session_token_manager.h"

SessionTokenManager& SessionTokenManager::instance() {
    static SessionTokenManager instance;
    return instance;
}

void SessionTokenManager::setToken(const std::string& token) {
    token_ = token;
    has_token_ = true;
}

void SessionTokenManager::setUsername(const std::string& username_in) {
    username = username_in;
}

const std::string& SessionTokenManager::getToken() const {
    if (!has_token_) {
        throw std::runtime_error("Session token not set");
    }
    return token_;
}

const std::string& SessionTokenManager::getUsername() const {
    return username;
}

bool SessionTokenManager::hasToken() const {
    return has_token_;
}

void SessionTokenManager::clearToken() {
    token_.clear();
    has_token_ = false;
}
