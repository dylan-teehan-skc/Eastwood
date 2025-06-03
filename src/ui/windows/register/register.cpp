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
    WindowManager::instance().showReceived();
}

void Register::onRegistrationError(const QString& title, const QString& message) {
    ui->registerButton->setText("Register");
    ui->registerButton->setEnabled(true);
    StyledMessageBox::error(this, title, message);
}

void Register::onRegisterButtonClicked() {
    // passphrase requirements as per NIST SP 800-63B guidelines
    constexpr int MAX_PASSPHRASE_LENGTH = 64;
    constexpr int MIN_PASSPHRASE_LENGTH = 20;
    constexpr int MAX_INPUT_LENGTH = 64;

    QString fullName = ui->fullNameEdit->text().left(MAX_INPUT_LENGTH);
    QString username = ui->usernameEdit->text().left(MAX_INPUT_LENGTH);
    QString passphrase = ui->passphraseEdit->text().left(MAX_PASSPHRASE_LENGTH);
    QString confirmPassphrase = ui->confirmPassphraseEdit->text().left(MAX_PASSPHRASE_LENGTH);

    ui->fullNameEdit->setText(fullName);
    ui->usernameEdit->setText(username);
    ui->passphraseEdit->setText(passphrase);
    ui->confirmPassphraseEdit->setText(confirmPassphrase);

    if (fullName.isEmpty() || username.isEmpty() || passphrase.isEmpty() || confirmPassphrase.isEmpty()) {
        StyledMessageBox::warning(this, "Error", "Please fill in all fields");
        return;
    }

    if (username.length() < 3) {
        StyledMessageBox::warning(this, "Error", "Username must be at least 3 characters long");
        return;
    }

    if (fullName.length() > MAX_INPUT_LENGTH || username.length() > MAX_INPUT_LENGTH) {
        StyledMessageBox::warning(this, "Error", "Input too long");
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

    // frontend passphrase logic
    if (passphrase != confirmPassphrase) {
        StyledMessageBox::warning(this, "Error", "Passphrases do not match");
        return;
    }

    // Update button state to show registration in progress
    ui->registerButton->setText("Registering...");
    ui->registerButton->setEnabled(false);

    // Run registration in separate thread to avoid blocking UI
    const auto _ = QtConcurrent::run([this, username, passphrase]() {
        try {
            register_user(username.toStdString(), std::make_unique<std::string>(passphrase.toStdString()));
            register_first_device();
            login_user(username.toStdString(), std::make_unique<std::string>(passphrase.toStdString()), false);

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
