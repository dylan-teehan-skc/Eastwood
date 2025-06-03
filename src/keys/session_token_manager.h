#pragma once
#include <string>
#include <stdexcept>

class SessionTokenManager {
public:
    static SessionTokenManager& instance();

    void setToken(const std::string& token);
    void setUsername(const std::string& username_in);
    const std::string& getToken() const;
    const std::string& getUsername() const;
    bool hasToken() const;
    void clearToken();

    // Non-copyable
    SessionTokenManager(const SessionTokenManager&) = delete;
    SessionTokenManager& operator=(const SessionTokenManager&) = delete;
private:
    SessionTokenManager() = default;
    std::string token_;
    std::string username;
    bool has_token_ = false;
}; 