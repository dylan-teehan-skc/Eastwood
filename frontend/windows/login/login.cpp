#include "./login.h"
#include "ui_login.h"
#include "../register/register.h"
#include "../../utils/messagebox.h"


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

    StyledMessageBox::info(this, "Success", "Login functionality here");
}

void Login::onRegisterButtonClicked()
{
    Register* registerWindow = new Register();
    // Pass the login window reference to the register window
    registerWindow->setLoginWindow(this);
    registerWindow->show();
    this->hide();
    // Make sure the register window gets deleted when closed
    registerWindow->setAttribute(Qt::WA_DeleteOnClose);
} 