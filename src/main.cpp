#include <QApplication>
#include "ui/windows/login/login.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    Login login;
    login.show();
    return app.exec();
}
