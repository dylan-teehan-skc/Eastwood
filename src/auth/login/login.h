//
// Created by Fred Sheppard on 28/05/2025.
//


#ifndef AUTH_LOGIN_H
#define AUTH_LOGIN_H
#include <string>
#include <memory>
#include "src/keys/secure_memory_buffer.h"

void login_user(
    const std::string &username, 
    std::unique_ptr<SecureMemoryBuffer>&& master_password, 
    bool is_new_device = false
);

#endif // AUTH_LOGIN_H
