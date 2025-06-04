#ifndef ENCRYPT_FILE_H
#define ENCRYPT_FILE_H
#include <string>
#include <tuple>

#include "src/keys/secure_memory_buffer.h"

std::string upload_file(
    const std::string &file_path,
    const std::unique_ptr<SecureMemoryBuffer> &f_kek
);

#endif //ENCRYPT_FILE_H
