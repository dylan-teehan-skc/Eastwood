#include <QApplication>
#include "ui/windows/login/login.h"
#include "./libraries/HTTPSClient.h"
#include <iostream>

int main(int argc, char *argv[]) {
    webwood::HTTPSClient httpclient;
    // std::string headers = "User-Agent: NiallClient/1.0\nAuthorization: Bearer abc123";
    // std::string body = "bod: bod";
    // std::string res = httpclient.post("webhook.site", "/86b5bc32-daa9-4f09-88eb-c658b71ae426", headers, body );
    // std::cout << res << std::endl;
    QApplication app(argc, argv);
    Login login;
    login.show();
    return app.exec();
}
