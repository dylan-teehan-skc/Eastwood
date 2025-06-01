#include "ui/windows/login/login.h"
#include "./libraries/HTTPSClient.h"
#include <iostream>
#define SQLITE_HAS_CODEC 1
#include <random>

#include "auth/login/login.h"
#include "auth/register_device/register_device.h"
#include "auth/register_user/register_user.h"
#include "client_api_interactions/MakeAuthReq.h"
#include "database/database.h"
#include "database/schema.h"
#include "endpoints/endpoints.h"
#include "sql/queries.h"
#include <memory>
#include "src/auth/rotate_master_key/rotate_master_key.h"

std::string generateRandomString(int length) {
    const std::string characters =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789";
    std::mt19937 generator(static_cast<unsigned int>(
        std::chrono::system_clock::now().time_since_epoch().count()
    ));
    std::uniform_int_distribution<> distribution(0, characters.length() - 1);
    std::string randomString;
    randomString.reserve(length);
    for (int i = 0; i < length; ++i) {
        randomString += characters[distribution(generator)];
    }
    return randomString;
}

int main() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }

    constexpr bool encrypted = true;
    constexpr bool refresh_database = true;

    const std::string username = generateRandomString(8);
    const auto master_key = SecureMemoryBuffer::create(MASTER_KEY_LEN);
    randombytes_buf(master_key->data(), MASTER_KEY_LEN);
    Database::get().initialize(username, master_key, encrypted);

    if (refresh_database) drop_all_tables();

    init_schema();

    auto password = std::make_unique<const std::string>("password1234");

    register_user(username, password);
    register_first_device();
    login_user(username, password);
    const std::string new_password = "even_stronger_password";
    rotate_master_password(username, new_password);
    post_new_keybundles(
        get_decrypted_keypair("device"),
        generate_signed_prekey(),
        generate_onetime_keys(100)
    );

    std::cout << "Integration main flow test completed successfully." << std::endl;
}
