#include "ui/windows/login/login.h"
#include "ui/windows/received_dashboard/received_dash.h"
#include "ui/windows/sent_dashboard/sent_dash.h"
#include "./libraries/HTTPSClient.h"
#include "ui/utils/window_manager/window_manager.h"
#include <iostream>
#define SQLITE_HAS_CODEC 1
#include <QApplication>
#include <random>
#include <QLabel>
#include <QString>
#include <sstream>
#include "client_api_interactions/MakeAuthReq.h"
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

    WindowManager::instance().showLogin();
    return app.exec();
}