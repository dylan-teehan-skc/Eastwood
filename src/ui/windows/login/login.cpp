#include "./login.h"
#include "src/auth/login/login.h"

#include "ui_login.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"

Login::Login(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Login)
{
    ui->setupUi(this);
    setupConnections();
}

Login::~Login()
{
    delete ui;
}

void Login::setupConnections()
{
    connect(ui->loginButton, &QPushButton::clicked, this, &Login::onLoginButtonClicked);
    connect(ui->registerButton, &QPushButton::clicked, this, &Login::onRegisterButtonClicked);
    connect(ui->togglePassphraseButton, &QPushButton::clicked, this, &Login::onTogglePassphraseClicked);
}

void Login::onLoginButtonClicked()
{
    // Maximum length as per NIST SP 800-63B (allowing up to 64 characters)
    const int MAX_PASSPHRASE_LENGTH = 64;
    const int MIN_PASSPHRASE_LENGTH = 20;
    
    QString username = ui->usernameEdit->text();
    QString passphrase = ui->passphraseEdit->text();
    
    if (username.isEmpty() || passphrase.isEmpty()) {
        StyledMessageBox::warning(this, "Error", "Please enter both username and passphrase");
        return;
    }

    if (username.length() < 3) {
        StyledMessageBox::warning(this, "Error", "Username must be at least 3 characters long");
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

    login_user(username.toStdString());

    StyledMessageBox::info(this, "Success", "Login functionality here");
}

void Login::onRegisterButtonClicked()
{
    WindowManager::instance().showRegister();
    hide();
}

void Login::onTogglePassphraseClicked()
{
    m_passphraseVisible = !m_passphraseVisible;
    ui->passphraseEdit->setEchoMode(m_passphraseVisible ? QLineEdit::Normal : QLineEdit::Password);
    ui->togglePassphraseButton->setText(m_passphraseVisible ? "Hide" : "Show");
} 