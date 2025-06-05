#ifndef SET_UP_CLIENT_H
#define SET_UP_CLIENT_H

#include <string>
#include <memory>
#include "src/keys/secure_memory_buffer.h"

void set_up_client_for_user(
    const std::string &username,
    std::unique_ptr<SecureMemoryBuffer>&& master_password,
    const bool DEBUG_REFRESH_TABLES = false
);

#endif // SET_UP_CLIENT_H
