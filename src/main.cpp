#include <iostream>
#define SQLITE_HAS_CODEC 1
#include <QFile>
#include <QApplication>
#include "ui/windows/login/login.h"
#include "client_api_interactions/MakeAuthReq.h"
#include "client_api_interactions/MakeUnauthReq.h"
#include "database/database.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    // NOTE: Debugging only. Refreshes the database on every run
    QFile::remove("/Users/fred/Library/Application Support/encrypted.db");
    auto &db = Database::get();
    if (db.initialize("master key")) {
        std::cout << "Database initialized successfully." << std::endl;
    } else {
        std::cout << "Failed to initialize database." << std::endl;
        return 1;
    }


    json response = get_auth("/posts/1");
    std::cout << response.dump(4) << std::endl;  // Pretty print with 4 spaces


    // std::string res2 = get_unauth("/posts/1");
    // std::cout << res2 << std::endl;

    // json data = {
    //     {"hello", "world"}  // Key-value pair in JSON object
    // };
    
    // std::string res3 = post_auth(data);
    // std::cout << res3 << std::endl;

    // std::string res4 = post_unauth();
    // std::cout << res4 << std::endl;

    // Login login;
    // login.show();
    // return app.exec();
}
