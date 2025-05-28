#pragma once
#include <string>
#include <stdexcept>

class SessionTokenManager {
public:
    static SessionTokenManager& instance();

    void setToken(const std::string& token);
    const std::string& getToken() const;
    bool hasToken() const;

    // Non-copyable
    SessionTokenManager(const SessionTokenManager&) = delete;
    SessionTokenManager& operator=(const SessionTokenManager&) = delete;
private:
    SessionTokenManager() = default;
    std::string token_;
    bool has_token_ = false;
}; 