#ifndef ROTATE_MASTER_KEY_H
#define ROTATE_MASTER_KEY_H
#include <string>
#include <memory>
#include "src/keys/secure_memory_buffer.h"

void rotate_master_password(
    const std::string &username,
    std::unique_ptr<SecureMemoryBuffer>&& old_password,
    std::unique_ptr<SecureMemoryBuffer>&& new_password
);

#endif //ROTATE_MASTER_KEY_H
