#include "./register.h"
#include "ui_register.h"
#include "src/ui/utils/messagebox.h"
#include "src/ui/utils/window_manager/window_manager.h"
#include "src/auth/register_user/register_user.h"
#include <iostream>
#include "src/auth/login/login.h"
#include "src/auth/register_device/register_device.h"
#include "src/utils/JsonParser.h"
#include <QScreen>
#include <QApplication>
#include <sodium.h>
#include "src/keys/secure_memory_buffer.h"

#include <QtConcurrent>

#include "src/algorithms/algorithms.h"
#include "src/endpoints/endpoints.h"
#include "src/sql/queries.h"

Register::Register(QWidget *parent)
    : QWidget(parent)
      , ui(new Ui::Register) {
    ui->setupUi(this);
    setupConnections();

    QScreen *screen = QApplication::primaryScreen();
    QRect screenGeometry = screen->geometry();
    int x = (screenGeometry.width() - width()) / 2;
    int y = (screenGeometry.height() - height()) / 2;
    move(x, y);
}

Register::~Register() {
    delete ui;
}

void Register::setupConnections() {
    connect(ui->loginButton, &QPushButton::clicked, this, &Register::onLoginButtonClicked);
    connect(ui->togglePassphraseButton, &QPushButton::clicked, this, &Register::onTogglePassphraseClicked);
    connect(ui->registerButton, &QPushButton::clicked, this, &Register::onRegisterButtonClicked);

    connect(this, &Register::registrationSuccess, this, &Register::onRegistrationSuccess);
    connect(this, &Register::registrationError, this, &Register::onRegistrationError);
}

void Register::onRegistrationSuccess() const {
    ui->registerButton->setText("Register");
    ui->registerButton->setEnabled(true);
    ui->passphraseEdit->clear();
    ui->confirmPassphraseEdit->clear();
    ui->fullNameEdit->clear();
    ui->usernameEdit->clear();
    WindowManager::instance().showReceived();
}

void Register::onRegistrationError(const QString& title, const QString& message) {
    ui->registerButton->setText("Register");
    ui->registerButton->setEnabled(true);
    StyledMessageBox::error(this, title, message);
}

void Register::onRegisterButtonClicked() {
    QString fullName = ui->fullNameEdit->text().trimmed();
    QString username = ui->usernameEdit->text().trimmed();
    QString passphrase = ui->passphraseEdit->text();
    QString confirmPassphrase = ui->confirmPassphraseEdit->text();

    // Validate full name
    QString nameError;
    if (!NameValidator::validateFullName(fullName, nameError)) {
        StyledMessageBox::warning(this, "Error", nameError);
        return;
    }

    // Validate username
    QString usernameError;
    if (!NameValidator::validateUsername(username, usernameError)) {
        StyledMessageBox::warning(this, "Error", usernameError);
        return;
    }

    // Validate passphrase
    QString errorMessage;
    if (!PassphraseValidator::validate(passphrase, confirmPassphrase, errorMessage)) {
        StyledMessageBox::warning(this, "Error", errorMessage);
        return;
    }

    // Update button state to show registration in progress
    ui->registerButton->setText("Registering...");
    ui->registerButton->setEnabled(false);

    // Move password to SecureMemoryBuffer immediately
    auto securePassphrase = SecureMemoryBuffer::create(passphrase.length());
    memcpy(securePassphrase->data(), passphrase.toUtf8().constData(), passphrase.length());
    
    // Clear the original QString
    passphrase.fill('\0');
    confirmPassphrase.fill('\0');

    // Run registration in separate thread to avoid blocking UI
    const auto _ = QtConcurrent::run([this, username = username.toStdString(), securePassphrase = std::move(securePassphrase)]() mutable {
        try {
            register_user(username, std::move(securePassphrase));
            register_first_device();
            
            // Create a new SecureMemoryBuffer for login
            auto loginPassphrase = SecureMemoryBuffer::create(securePassphrase->size());
            memcpy(loginPassphrase->data(), securePassphrase->data(), securePassphrase->size());
            
            login_user(username, std::move(loginPassphrase), false);

            auto signed_prekey = generate_signed_prekey();
            post_new_keybundles(
                get_decrypted_keypair("device"),
                &signed_prekey,
                generate_onetime_keys(50)
                );
            emit registrationSuccess();

        } catch (const webwood::HttpError &e) {
            const std::string errorBody = e.what();
            const bool isHtmlError = errorBody.find("<!DOCTYPE HTML") != std::string::npos;
            const QString title = isHtmlError ? "Server Unavailable" : "Registration Failed";
            const QString message = isHtmlError
                                        ? "The server is currently unavailable. Please try again later."
                                        : QString("Registration failed: %1").arg(QString::fromStdString(errorBody));
            emit registrationError(title, message);

        } catch (const std::exception &e) {
            const QString errorMsg = QString("An error occurred: %1").arg(e.what());
            emit registrationError("Registration Failed", errorMsg);
        }
    });
}

void Register::onLoginButtonClicked() {
    WindowManager::instance().showLogin();
}

void Register::onTogglePassphraseClicked() {
    m_passphraseVisible = !m_passphraseVisible;
    ui->passphraseEdit->setEchoMode(m_passphraseVisible ? QLineEdit::Normal : QLineEdit::Password);
    ui->confirmPassphraseEdit->setEchoMode(m_passphraseVisible ? QLineEdit::Normal : QLineEdit::Password);
    ui->togglePassphraseButton->setText(m_passphraseVisible ? "Hide" : "Show");
}
