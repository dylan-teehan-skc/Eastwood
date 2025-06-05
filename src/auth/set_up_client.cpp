#include <memory>
#include <sodium.h>
#include <stdexcept>

#include "salt.h"
#include "src/algorithms/algorithms.h"
#include "src/database/database.h"
#include "src/database/schema.h"
#include "src/endpoints/endpoints.h"
#include "src/keys/kek_manager.h"
#include "src/keys/secure_memory_buffer.h"

void set_up_client_for_user(
    const std::string &username,
    std::unique_ptr<SecureMemoryBuffer>&& master_password,
    const bool DEBUG_REFRESH_TABLES = false
) {
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed\n");
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof salt);

    const auto master_key = derive_master_key(std::move(master_password), salt);
    save_salt_to_file(username, salt);

    Database::get().initialize(username, master_key);;
    if (DEBUG_REFRESH_TABLES) drop_all_tables();
    init_schema();

    auto kek = SecureMemoryBuffer::create(SYM_KEY_LEN);
    crypto_secretbox_keygen(kek->data());

    unsigned char nonce_kek[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce_kek, sizeof(nonce_kek));

    const auto encrypted_kek = encrypt_kek(kek, nonce_kek, master_key);
    KekManager::instance().setKEK(std::move(kek));

    save_encrypted_key("kek", encrypted_kek, nonce_kek);
    // TODO
    // post_new_keybundles()
}
