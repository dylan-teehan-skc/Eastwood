#include <vector>
#include <sodium.h>

#include "src/algorithms/constants.h"
#include "src/communication/send_file_to/send_file_to.h"
#include "src/endpoints/endpoints.h"
#include "src/keys/secure_memory_buffer.h"

void refresh_access(const std::vector<std::string> &allowed_usernames, const std::string &file_uuid) {
    post_revoke_file_access(file_uuid);

    const auto new_file_key = SecureMemoryBuffer::create(SYM_KEY_LEN);
    const auto new_fkek = SecureMemoryBuffer::create(SYM_KEY_LEN);
    randombytes_buf(new_file_key->data(), new_file_key->size());
    randombytes_buf(new_fkek->data(), new_fkek->size());

    const auto encrypted_file_key = encrypt_message_given_key(
        new_file_key->data(), new_file_key->size(),
        new_fkek->data()
    );

    post_update_file_key(file_uuid, encrypted_file_key);
    for (const auto username: allowed_usernames) {
        allow_access_to_file(username, file_uuid, new_fkek);
    }
}
