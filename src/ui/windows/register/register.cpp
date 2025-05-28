#include "./register.h"
#include "ui_register.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "src/auth/register_user/register_user.h"
#include <iostream>
#include "src/auth/register_device/register_device.h"
#include "src/utils/JsonParser.h"


Register::Register(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Register)
{
    ui->setupUi(this);
    setupConnections();
}

Register::~Register()
{
    delete ui;
}

void Register::setupConnections()
{
    connect(ui->loginButton, &QPushButton::clicked, this, &Register::onLoginButtonClicked);
    connect(ui->togglePassphraseButton, &QPushButton::clicked, this, &Register::onTogglePassphraseClicked);
    connect(ui->registerButton, &QPushButton::clicked, this, &Register::onRegisterButtonClicked);
}

void Register::onRegisterButtonClicked()
{
    // passphrase requirements as per NIST SP 800-63B guidelines
    const int MAX_PASSPHRASE_LENGTH = 64;
    const int MIN_PASSPHRASE_LENGTH = 20;
    const int MAX_INPUT_LENGTH = 64;

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

    try {
        register_user(username.toStdString(), std::make_unique<std::string>(passphrase.toStdString()));
        register_first_device();
        StyledMessageBox::info(this, "Success", "Registration successful!");
        WindowManager::instance().showLogin();
        hide();
    } catch (const webwood::HttpError& e) {
        // Extract the error body from the response
        std::string errorBody = e.what();
        StyledMessageBox::error(this, "Registration Failed", 
            QString("Registration failed: %1").arg(QString::fromStdString(errorBody)));
    } catch (const std::exception& e) {
        StyledMessageBox::error(this, "Registration Failed", 
            QString("An error occurred: %1").arg(e.what()));
    }
}

void Register::onLoginButtonClicked()
{
    // TODO: do on backend for NIST SP 800-63B standard
    // 1. Blocklist commonly used passphrases
    // 2. Passphrases from known breaches
    // 3. Context-specific words (username, app name, etc.)
    // Do NOT implement complexity requirements (uppercase, numbers, special chars)
    
    WindowManager::instance().showLogin();
    hide();
}

void Register::onTogglePassphraseClicked()
{
    m_passphraseVisible = !m_passphraseVisible;
    ui->passphraseEdit->setEchoMode(m_passphraseVisible ? QLineEdit::Normal : QLineEdit::Password);
    ui->confirmPassphraseEdit->setEchoMode(m_passphraseVisible ? QLineEdit::Normal : QLineEdit::Password);
    ui->togglePassphraseButton->setText(m_passphraseVisible ? "Hide" : "Show");
} 
