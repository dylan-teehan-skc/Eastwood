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
#include "key_exchange/utils.h"
#include "sessions/IdentityManager.h"
#include "sessions/IdentitySession.h"
#include "sql/queries.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    constexpr bool encrypted = true;
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

    register_user("sloggotest22", std::make_unique<std::string>("1250"));
    register_first_device();
    login_user("sloggotest22");
    post_new_keybundles(
        get_decrypted_keypair("device"),
        generate_signed_prekey(),
        generate_onetime_keys(100)
    );

    std::cout << "Press Enter to run /incomingMessages";
    std::cin.get();

    auto backlog = get_handshake_backlog();
    IdentityManager::getInstance().update_or_create_identity_sessions(backlog);

    std::cout << "Press Enter to run";
    std::cin.get();

    auto random_bytes = new unsigned char[5];
    randombytes_buf(random_bytes, 5);

    auto backlog2 = IdentityManager::getInstance().send_to_user("nialltest22", random_bytes);
    post_ratchet_message(backlog2);
    delete[] random_bytes;

    // WindowManager::instance().showLogin();
    return app.exec();
}