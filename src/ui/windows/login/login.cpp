#include "./login.h"
#include "src/auth/login/login.h"
#include "src/endpoints/endpoints.h"
#include "ui_login.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "src/sql/queries.h"
#include "src/key_exchange/utils.h"
#include "src/ui/utils/qr_code_generation/QRCodeGenerator.h"
#include <sodium.h>
#include <QDebug>
#include "src/database/database.h"
#include "src/auth/set_up_client.h"
#include <QInputDialog>

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

bool Login::validateUsername(const QString& username) {
    if (username.isEmpty()) {
        StyledMessageBox::warning(this, "Error", "Please enter a username");
        return false;
    }

    if (username.length() < 3) {
        StyledMessageBox::warning(this, "Error", "Username must be at least 3 characters long");
        return false;
    }

    return true;
}

QString Login::getAndValidatePassword() {
    bool passwordAccepted;
    QString password = QInputDialog::getText(this, "Set Password", 
        "Enter a password (20-64 characters):", 
        QLineEdit::Password, "", &passwordAccepted);
    
    if (!passwordAccepted || password.isEmpty()) {
        StyledMessageBox::error(this, "Error", "Password is required");
        return QString();
    }

    if (password.length() < 20) {
        StyledMessageBox::error(this, "Error", "Password must be at least 20 characters long");
        return QString();
    }

    if (password.length() > 64) {
        StyledMessageBox::error(this, "Error", "Password cannot be longer than 64 characters");
        return QString();
    }

    QString verifyPassword = QInputDialog::getText(this, "Verify Password", 
        "Enter the password again:", 
        QLineEdit::Password, "", &passwordAccepted);
    
    if (!passwordAccepted || verifyPassword.isEmpty()) {
        StyledMessageBox::error(this, "Error", "Password verification is required");
        return QString();
    }

    if (password != verifyPassword) {
        StyledMessageBox::error(this, "Error", "Passwords do not match");
        return QString();
    }

    return password;
}

std::tuple<std::string, QImage, std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>, std::unique_ptr<SecureMemoryBuffer>> Login::setupDeviceRegistration() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Libsodium initialization failed");
    }

    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pk_device;
    auto sk_device = SecureMemoryBuffer::create(crypto_sign_SECRETKEYBYTES);

    crypto_sign_keypair(pk_device.data(), sk_device->data());
    std::string auth_code = bin2base64(pk_device.data(), crypto_sign_PUBLICKEYBYTES);
    QImage qr_code = getQRCodeForMyDevicePublicKey(bin2base64(pk_device.data(), 32));

    if (auth_code.empty()) {
        throw std::runtime_error("Failed to generate authentication code");
    }

    if (qr_code.isNull()) {
        throw std::runtime_error("Failed to generate QR code");
    }

    return std::make_tuple(std::move(auth_code), std::move(qr_code), std::move(pk_device), std::move(sk_device));
}

void Login::initializeDatabase(const std::string& username, const QString& password, 
                             std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>& pk_device, 
                             std::unique_ptr<SecureMemoryBuffer>& sk_device) {
    auto master_password = std::make_unique<std::string>(password.toStdString());
    set_up_client_for_user(username, std::move(master_password));

    // Save the device keypair to the database
    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, CHA_CHA_NONCE_LEN);
    const auto esk_device = encrypt_secret_key(sk_device, nonce);
    save_encrypted_keypair("device", pk_device.data(), esk_device, nonce);
}

void Login::onContinueButtonClicked()
{
    QString username = ui->usernameEdit->text();
    
    if (!validateUsername(username)) {
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
            
            auto [auth_code, qr_code, pk_device, sk_device] = setupDeviceRegistration();
            
            WindowManager::instance().showDeviceRegister(auth_code, qr_code, pk_device.data(), std::move(sk_device), username.toStdString());
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
    constexpr int MAX_PASSPHRASE_LENGTH = 64;
    constexpr int MIN_PASSPHRASE_LENGTH = 20;
    
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
        ui->passphraseEdit->clear();
        ui->usernameEdit->clear();
        WindowManager::instance().showReceived();
    } catch (const std::exception& e) {
        StyledMessageBox::error(this, "Login Failed", QString("Failed to login: %1").arg(e.what()));
    }
}

void Login::onRegisterButtonClicked()
{
    ui->passphraseEdit->clear();
    ui->usernameEdit->clear();
    WindowManager::instance().showRegister();
}

void Login::onTogglePassphraseClicked()
{
    m_passphraseVisible = !m_passphraseVisible;
    ui->passphraseEdit->setEchoMode(m_passphraseVisible ? QLineEdit::Normal : QLineEdit::Password);
    ui->togglePassphraseButton->setText(m_passphraseVisible ? "Hide" : "Show");
}

void Login::showPassphraseStage() const {
    ui->passphraseEdit->show();
    ui->togglePassphraseButton->show();
    ui->loginButton->show();
    ui->continueButton->hide();
    ui->logoLabel->hide();
    ui->passphraseEdit->setFocus();
}

void Login::hidePassphraseStage() {
    ui->passphraseEdit->hide();
    ui->togglePassphraseButton->hide();
    ui->loginButton->hide();
    ui->continueButton->show();
    ui->logoLabel->show();
    ui->usernameEdit->setFocus();
}

void Login::showUsernameStage() const {
    ui->passphraseEdit->hide();
    ui->togglePassphraseButton->hide();
    ui->loginButton->hide();
    ui->continueButton->show();
    ui->logoLabel->show();
    ui->usernameEdit->setFocus();
} 