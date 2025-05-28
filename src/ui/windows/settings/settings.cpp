#include "settings.h"
#include "ui_settings.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "../../utils/navbar/navbar.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileInfo>
#include <QFileDialog>
#include <QLineEdit>
#include <QDialog>
#include <QScrollArea>
#include <QTimer>
#include <QCheckBox>

Settings::Settings(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Settings)
{
    ui->setupUi(this);
    setupConnections();

    // Connect WindowManager signal to handle navbar highlighting
    connect(&WindowManager::instance(), &WindowManager::windowShown,
            this, &Settings::onWindowShown);
}

Settings::~Settings()
{
    delete ui;
}

void Settings::setupConnections()
{
    // Connect passphrase fields to validation
    connect(ui->currentPassphrase, &QLineEdit::textChanged, this, &Settings::validatePassphrase);
    connect(ui->newPassphrase, &QLineEdit::textChanged, this, &Settings::validatePassphrase);
    connect(ui->confirmPassphrase, &QLineEdit::textChanged, this, &Settings::validatePassphrase);

    // Connect buttons
    connect(ui->cancelButton, &QPushButton::clicked, this, &Settings::onCancelClicked);

    // Connect NavBar signals
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        connect(navbar, &NavBar::receivedClicked, this, &Settings::onReceivedButtonClicked);
        connect(navbar, &NavBar::sentClicked, this, &Settings::onSentButtonClicked);
        connect(navbar, &NavBar::sendFileClicked, this, &Settings::onSendFileButtonClicked);
        connect(navbar, &NavBar::logoutClicked, this, &Settings::onLogoutButtonClicked);
        connect(navbar, &NavBar::settingsClicked, this, &Settings::onSettingsButtonClicked);
    }
}

void Settings::validatePassphrase()
{
    QString newPassphrase = ui->newPassphrase->text();
    QString confirmPassphrase = ui->confirmPassphrase->text();

    if (newPassphrase.isEmpty() && confirmPassphrase.isEmpty()) {
        ui->passphraseRequirements->setText("Passphrase must be between 20 and 64 characters");
        ui->passphraseRequirements->setStyleSheet("font-size: 12px; color: #636e72; margin-top: 5px;");
        return;
    }

    if (newPassphrase == confirmPassphrase) {
        ui->passphraseRequirements->setText("Passphrases match");
        ui->passphraseRequirements->setStyleSheet("font-size: 12px; color: #27ae60; margin-top: 5px;");
    } else {
        ui->passphraseRequirements->setText("Passphrases do not match");
        ui->passphraseRequirements->setStyleSheet("font-size: 12px; color: #e74c3c; margin-top: 5px;");
    }
}

void Settings::navigateTo(QWidget* newWindow)
{
    newWindow->setParent(this->parentWidget());  // Set the same parent
    newWindow->show();
    this->setAttribute(Qt::WA_DeleteOnClose);  // Mark for deletion when closed
    close();  // This will trigger deletion due to WA_DeleteOnClose
}

void Settings::onReceivedButtonClicked()
{
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showReceived();
    hide();
}

void Settings::onSentButtonClicked()
{
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showSent();
    hide();
}

void Settings::onSendFileButtonClicked()
{   
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showSendFile();
    hide();
}

void Settings::onSettingsButtonClicked()
{   
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
}

void Settings::onWindowShown(const QString& windowName)
{
    // Find the navbar and update its active button
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        navbar->setActiveButton(windowName);
    }
}

void Settings::onCancelClicked()
{
    // Clear all passphrase fields
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    
    // Navigate back to the previous window
    WindowManager::instance().showReceived();
    hide();
}

void Settings::onLogoutButtonClicked() {
    // TODO: Implement logout functionality
    StyledMessageBox::info(this, "Not Implemented", "Logout functionality is not yet implemented.");
}
