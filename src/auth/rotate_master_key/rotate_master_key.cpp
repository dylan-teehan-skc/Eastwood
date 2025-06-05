#include <string>

#include <sodium.h>

#include "src/auth/salt.h"
#include "src/algorithms/algorithms.h"
#include "src/database/database.h"
#include "src/keys/kek_manager.h"
#include "src/sql/queries.h"

void rotate_master_password(
    const std::string &username,
    std::unique_ptr<SecureMemoryBuffer>&& old_password,
    std::unique_ptr<SecureMemoryBuffer>&& new_password
) {
    if (!KekManager::instance().isLoaded()) {
        throw std::runtime_error("Unable to rotate master password - KEK has not been loaded");
    }

    unsigned char old_salt[crypto_pwhash_SALTBYTES];
    get_salt_from_file(username, old_salt);
    const auto old_key = derive_master_key(std::move(old_password), old_salt);

    unsigned char new_salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(new_salt, crypto_pwhash_SALTBYTES);

    const auto new_key = derive_master_key(std::move(new_password), new_salt);
    Database::get().rotate_master_key(old_key, new_key);
    save_salt_to_file(username, new_salt);

    const auto kek = KekManager::instance().getKEK();
    const auto kek_copy = SecureMemoryBuffer::create(SYM_KEY_LEN);
    memcpy(kek_copy->data(), kek->data(), SYM_KEY_LEN);

    unsigned char new_nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(new_nonce, CHA_CHA_NONCE_LEN);

    const auto encrypted_kek = encrypt_kek(kek_copy, new_nonce, new_key);
    save_encrypted_key("kek", encrypted_kek, new_nonce);
}
