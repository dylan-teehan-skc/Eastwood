//
// Created by Fred Sheppard on 28/05/2025.
//


#ifndef AUTH_LOGIN_H
#define AUTH_LOGIN_H
#include <string>
#include <memory>

void login_user(const std::string &username, const std::unique_ptr<const std::string> &master_password);

#endif //AUTH_LOGIN_H
