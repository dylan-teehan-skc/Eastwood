#ifndef SEND_FILE_TO_H
#define SEND_FILE_TO_H
#include <string>
#include <memory>
#include "src/keys/secure_memory_buffer.h"

void allow_access_to_file(
    const std::string &username,
    const std::string &uuid,
    const std::unique_ptr<SecureMemoryBuffer> &f_kek,
    bool get_keybundles = true
);

void send_file_to(const std::string &username, const std::string &file_path, bool get_keybundles);

#endif //SEND_FILE_TO_H
