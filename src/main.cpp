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
    // Test generate_unique_id_pair
    std::string input1 = "test1";
    std::string input2 = "test2";
    unsigned char *result = generate_unique_id_pair(&input1, &input2);
    
    std::cout << "Testing generate_unique_id_pair:" << std::endl;
    std::cout << "Input 1: " << input1 << std::endl;
    std::cout << "Input 2: " << input2 << std::endl;
    std::cout << "Result hex: ";
    for (size_t i = 0; i < crypto_hash_sha256_BYTES; i++) {
        printf("%02x", result[i]);
    }
    std::cout << std::endl;
    std::cout << "Result length: " << crypto_hash_sha256_BYTES << " bytes" << std::endl;
    delete[] result;  // Clean up the result buffer
    
    std::cout << "\nStarting main application...\n" << std::endl;

    QApplication app(argc, argv);
    constexpr bool refresh_database = false;

    auto &db = Database::get();
    if (db.initialize("master key")) {
        qDebug() << "Database initialized successfully.";
    } else {
        qDebug() << "Failed to initialize database.";
        return 1;
    }

    // TODO: Debugging only
    if (refresh_database) drop_all_tables();

    init_schema();
    WindowManager::instance().showLogin();

    WindowManager::instance().showLogin();
    return QApplication::exec();
}