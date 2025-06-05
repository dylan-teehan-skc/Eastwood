#include "./libraries/HTTPSClient.h"
#include "ui/utils/window_manager/window_manager.h"
#define SQLITE_HAS_CODEC 1
#include <QApplication>
#include <random>

#include "database/schema.h"
#include "endpoints/endpoints.h"
#include "key_exchange/utils.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }

    WindowManager::instance().showLogin();
    return app.exec();
}
