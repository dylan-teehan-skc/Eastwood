#include "ui/windows/login/login.h"
#include "ui/windows/received_dashboard/received_dash.h"
#include "ui/windows/sent_dashboard/sent_dash.h"
#include "./libraries/HTTPSClient.h"
#include "ui/utils/window_manager/window_manager.h"
#include <iostream>
#define SQLITE_HAS_CODEC 1
#include <QFile>
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
    constexpr bool encrypted = false;
    constexpr bool refresh_database = true;

    auto &db = Database::get();
    if (db.initialize("master key", encrypted)) {
        std::cout << "Database initialized successfully." << std::endl;
    } else {
        std::cerr << "Failed to initialize database." << std::endl;
        return 1;
    }

    auto master_password = std::make_unique<std::string>("correct horse battery stapler");

    if (refresh_database) drop_all_tables();

    init_schema();

    const std::string username = generateRandomString(8);
    register_user(username, std::make_unique<std::string>("1234"));
    register_first_device();
    login_user(username);
    post_new_keybundles(
        get_decrypted_keypair("device"),
        generate_signed_prekey(),
        generate_onetime_keys(100)
    );


    std::cout << "Integration main flow test completed successfully." << std::endl;
    return 0;
} 