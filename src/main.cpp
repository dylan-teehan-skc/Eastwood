#include "ui/windows/login/login.h"
#include "ui/windows/received_dashboard/received_dash.h"
#include "ui/windows/sent_dashboard/sent_dash.h"
#include "./libraries/HTTPSClient.h"
#include "ui/utils/window_manager/window_manager.h"
#include <iostream>
#define SQLITE_HAS_CODEC 1
#include <QFile>
#include <QApplication>
#include <random>

#include "auth/login/login.h"
#include "auth/register_device/register_device.h"
#include "auth/register_user/register_user.h"
#include "auth/login/login.h"
#include "client_api_interactions/MakeAuthReq.h"
#include "src/auth/login/login.h"
#include "database/database.h"
#include "database/schema.h"
#include "endpoints/endpoints.h"
#include "keys/session_token_manager.h"
#include "sql/queries.h"

std::string generateRandomString(int length) {
    // Define the characters you want to include in your random string.
    // This example uses uppercase letters, lowercase letters, and digits.
    const std::string characters =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789";

    // Seed the random number generator.
    // Using std::chrono::system_clock::now().time_since_epoch().count()
    // provides a good, time-based seed.
    std::mt19937 generator(static_cast<unsigned int>(
        std::chrono::system_clock::now().time_since_epoch().count()
    ));

    // Create a distribution to pick random indices from the 'characters' string.
    std::uniform_int_distribution<> distribution(0, characters.length() - 1);

    std::string randomString;
    randomString.reserve(length); // Pre-allocate memory for efficiency

    for (int i = 0; i < length; ++i) {
        randomString += characters[distribution(generator)];
    }

    return randomString;
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    constexpr bool encrypted = false;
    constexpr bool refresh_database = true;

    auto &db = Database::get();
    if (db.initialize("master key", encrypted)) {
        qDebug() << "Database initialized successfully.";
    } else {
        qDebug() << "Failed to initialize database.";
        return 1;
    }

    auto master_password = std::make_unique<std::string>("correct horse battery stapler");

    // TODO: Debugging only
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
    get_keybundles("dill3kco");


    // WindowManager::instance().showLogin();
    return app.exec();
}