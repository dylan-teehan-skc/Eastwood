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
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }

    WindowManager::instance().showLogin();
    return app.exec();
}
