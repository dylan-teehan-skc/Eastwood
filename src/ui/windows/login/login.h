#ifndef LOGIN_H
#define LOGIN_H

#include <QWidget>
#include <QString>
#include <tuple>
#include <memory>
#include <array>
#include <sodium.h>
#include "src/keys/secure_memory_buffer.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Login; }
QT_END_NAMESPACE

class Login : public QWidget {
    Q_OBJECT

public:
    explicit Login(QWidget *parent = nullptr);
    ~Login() override;

    void hidePassphraseStage();

private slots:
    void onContinueButtonClicked();
    void onLoginButtonClicked();
    void onRegisterButtonClicked();
    void onTogglePassphraseClicked();

private:
    Ui::Login *ui;
    void setupConnections();
    bool m_passphraseVisible = false;
    void showPassphraseStage() const;
    void showUsernameStage() const;

    // New helper functions
    bool validateUsername(const QString& username);
    QString getAndValidatePassword();
    std::tuple<std::string, QImage, std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>, std::unique_ptr<SecureMemoryBuffer>> setupDeviceRegistration();
    void initializeDatabase(const std::string& username, const QString& password, 
                          std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>& pk_device, 
                          std::unique_ptr<SecureMemoryBuffer>& sk_device);
};

#endif //LOGIN_H
