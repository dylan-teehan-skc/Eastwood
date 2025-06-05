#ifndef SIGNUP_H
#define SIGNUP_H
#include <string>
#include <memory>
#include "src/keys/secure_memory_buffer.h"

void register_user(
    const std::string &username,
    std::unique_ptr<SecureMemoryBuffer>&& master_password,
    const bool DEBUG_REFRESH_TABLES = false
);

#endif // SIGNUP_H
