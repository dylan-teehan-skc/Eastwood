#include <iostream>
#define SQLITE_HAS_CODEC 1
#include <QFile>
#include <QApplication>
#include "ui/windows/login/login.h"

#include "auth/register_device/register_device.h"
#include "auth/register_user/register_user.h"
#include "database/database.h"
#include "database/schema.h"
#include "endpoints/endpoints.h"
#include "sql/queries.h"
#include "utils/ConversionUtils.h"

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


    QByteArray encrypted_kek, nonce;
    try {
        get_encrypted_key("kek");
        qDebug() << "Existing KEK found. Skipping user registration";
        // login_user(master_password);
    } catch (const std::exception) {
        qDebug() << "KEK not found. Registering new user...";
        register_user("fred", std::move(master_password));
        register_first_device();
    }

    // TODO - This will go in login_user
    // auto kek = decrypt_kek(
    //     reinterpret_cast<unsigned char *>(encrypted_kek.data()),
    //     reinterpret_cast<unsigned char *>(nonce.data()),
    //     std::move(master_key)
    // );
    // KekManager::instance().setKEK(std::move(kek));

    Login login;
    login.show();
    return app.exec();
}
