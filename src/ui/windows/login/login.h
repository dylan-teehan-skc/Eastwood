#ifndef LOGIN_H
#define LOGIN_H

#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class Login; }
QT_END_NAMESPACE

class Login : public QWidget {
    Q_OBJECT

public:
    explicit Login(QWidget *parent = nullptr);
    ~Login() override;

private slots:
    void onLoginButtonClicked();
    void onRegisterButtonClicked();

private:
    Ui::Login *ui;
    void setupConnections();
};

#endif //LOGIN_H
