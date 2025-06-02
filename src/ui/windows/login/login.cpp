#include "./login.h"
#include "src/auth/login/login.h"
#include "src/endpoints/endpoints.h"
#include "ui_login.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "src/sql/queries.h"
#include "src/auth/register_device/register_device.h"
#include "src/key_exchange/utils.h"
#include "src/ui/utils/qr_code_generation/QRCodeGenerator.h"
#include <sodium.h>
#include <QDebug>
#include "src/database/database.h"

Login::Login(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Login)
{
    ui->setupUi(this);
    setupConnections();
    
    ui->passphraseEdit->hide();
    ui->togglePassphraseButton->hide();
    ui->loginButton->hide();
}

Login::~Login()
{
    delete ui;
}

void Login::setupConnections()
{
    connect(ui->continueButton, &QPushButton::clicked, this, &Login::onContinueButtonClicked);
    connect(ui->loginButton, &QPushButton::clicked, this, &Login::onLoginButtonClicked);
    connect(ui->registerButton, &QPushButton::clicked, this, &Login::onRegisterButtonClicked);
    connect(ui->togglePassphraseButton, &QPushButton::clicked, this, &Login::onTogglePassphraseClicked);
}

void Login::onContinueButtonClicked()
{
    QString username = ui->usernameEdit->text();
    
    if (username.isEmpty()) {
        StyledMessageBox::warning(this, "Error", "Please enter a username");
        return;
    }

    if (username.length() < 3) {
        StyledMessageBox::warning(this, "Error", "Username must be at least 3 characters long");
        return;
    }

    try {
        bool existsOnServer = get_user_exists(username.toStdString());
        bool hasDatabase = Database::user_has_database(username.toStdString());

        if (hasDatabase && existsOnServer) {
            qDebug() << "User has database and exists on server";
            showPassphraseStage();
        } else if (existsOnServer) {
            qDebug() << "User exists on server but no local database - register new device";
            // User exists on server but no local database - register new device
            if (sodium_init() < 0) {
                throw std::runtime_error("Libsodium initialization failed");
            }

            unsigned char pk_device[crypto_sign_PUBLICKEYBYTES];
            const auto sk_device = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);

            crypto_sign_keypair(pk_device, sk_device->data());
            std::string auth_code = bin2base64(pk_device, crypto_sign_PUBLICKEYBYTES);
            QImage qr_code = getQRCodeForMyDevicePublicKey(bin2base64(pk_device, 32));

            if (auth_code.empty()) {
                StyledMessageBox::error(this, "Device Registration Failed", "Failed to generate authentication code");
                return;
            }

            if (qr_code.isNull()) {
                StyledMessageBox::error(this, "Device Registration Failed", "Failed to generate QR code");
                return;
            }

            WindowManager::instance().showDeviceRegister(auth_code, qr_code, pk_device);
        } else {
            qDebug() << "User doesn't exist - go straight to register";
            WindowManager::instance().showRegister();
        }
    } catch (const std::exception& e) {
        StyledMessageBox::error(this, "Error", QString("Failed to check user existence: %1").arg(e.what()));
    }
}

void Login::onLoginButtonClicked()
{
    // Maximum length as per NIST SP 800-63B (allowing up to 64 characters)
    const int MAX_PASSPHRASE_LENGTH = 64;
    const int MIN_PASSPHRASE_LENGTH = 20;
    
    QString username = ui->usernameEdit->text();
    QString passphrase = ui->passphraseEdit->text();
    
    if (passphrase.isEmpty()) {
        StyledMessageBox::warning(this, "Error", "Please enter your passphrase");
        return;
    }

    if (passphrase.length() < MIN_PASSPHRASE_LENGTH) {
        StyledMessageBox::warning(this, "Error", "Passphrase must be at least 20 characters long");
        return;
    }

    if (passphrase.length() > MAX_PASSPHRASE_LENGTH) {
        StyledMessageBox::warning(this, "Error", "Passphrase cannot be longer than 64 characters");
        return;
    }

    try {
        login_user(username.toStdString(), std::make_unique<std::string>(passphrase.toStdString()));
        WindowManager::instance().showReceived();
    } catch (const std::exception& e) {
        StyledMessageBox::error(this, "Login Failed", QString("Failed to login: %1").arg(e.what()));
    }
}

void Login::onRegisterButtonClicked()
{
    WindowManager::instance().showRegister();
}

void Login::onTogglePassphraseClicked()
{
    m_passphraseVisible = !m_passphraseVisible;
    ui->passphraseEdit->setEchoMode(m_passphraseVisible ? QLineEdit::Normal : QLineEdit::Password);
    ui->togglePassphraseButton->setText(m_passphraseVisible ? "Hide" : "Show");
}

void Login::showPassphraseStage()
{
    ui->passphraseEdit->show();
    ui->togglePassphraseButton->show();
    ui->loginButton->show();
    ui->continueButton->hide();
    ui->passphraseEdit->setFocus();
}

void Login::showUsernameStage()
{
    ui->passphraseEdit->hide();
    ui->togglePassphraseButton->hide();
    ui->loginButton->hide();
    ui->continueButton->show();
    ui->usernameEdit->setFocus();
} 