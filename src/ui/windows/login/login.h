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
    void onContinueButtonClicked();
    void onLoginButtonClicked();
    void onRegisterButtonClicked();
    void onTogglePassphraseClicked();

private:
    Ui::Login *ui;
    void setupConnections();
    bool m_passphraseVisible = false;
    void showPassphraseStage();
    void showUsernameStage();
};

#endif //LOGIN_H
