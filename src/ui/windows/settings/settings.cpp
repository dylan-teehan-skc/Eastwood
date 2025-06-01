#include "settings.h"
#include "ui_settings.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "../../utils/navbar/navbar.h"
#include "src/key_exchange/utils.h"
#include "src/auth/register_device/register_device.h"
#include "src/utils/ConversionUtils.h"
#include <QVBoxLayout>
#include <QFileDialog>
#include <QLineEdit>
#include <QDialog>
#include <QTimer>
#include <QCheckBox>
#include <QImage>
#include <QImageReader>
#include <QPixmap>
#include <QLabel>
#include <QDebug>

Settings::Settings(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Settings)
    , m_cameraFunctionality(new CameraFunctionality(this))
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
    connect(ui->currentPassphrase, &QLineEdit::textChanged, this, &Settings::validatePassphrase);
    connect(ui->confirmPassphrase, &QLineEdit::textChanged, this, &Settings::validatePassphrase);

    // Connect passphrase section buttons
    connect(ui->passphraseCancelButton, &QPushButton::clicked, this, &Settings::onPassphraseCancelClicked);
    connect(ui->passphraseSaveButton, &QPushButton::clicked, this, &Settings::onPassphraseSaveClicked);

    // Connect auth section buttons
    connect(ui->authCancelButton, &QPushButton::clicked, this, &Settings::onAuthCancelClicked);
    connect(ui->authSaveButton, &QPushButton::clicked, this, &Settings::onAuthSaveClicked);

    // Connect NavBar signals
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        connect(navbar, &NavBar::receivedClicked, this, &Settings::onReceivedButtonClicked);
        connect(navbar, &NavBar::sentClicked, this, &Settings::onSentButtonClicked);
        connect(navbar, &NavBar::sendFileClicked, this, &Settings::onSendFileButtonClicked);
        connect(navbar, &NavBar::logoutClicked, this, &Settings::onLogoutButtonClicked);
        connect(navbar, &NavBar::settingsClicked, this, &Settings::onSettingsButtonClicked);
    }
    connect(ui->scanQRButton, &QPushButton::clicked, this, &Settings::onScanQRButtonClicked);
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
}

void Settings::onSentButtonClicked()
{
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showSent();
}

void Settings::onSendFileButtonClicked()
{   
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showSendFile();
}

void Settings::onSettingsButtonClicked()
{   
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
}

void Settings::onWindowShown(const QString& windowName) const
{
    // Find the navbar and update its active button
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        navbar->setActiveButton(windowName);
    }
}

void Settings::onPassphraseCancelClicked()
{
    // Clear all passphrase fields
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    
    // Navigate back to the previous window
    WindowManager::instance().showReceived();
}

void Settings::onPassphraseSaveClicked()
{
    // TODO: Implement passphrase change functionality
    StyledMessageBox::info(this, "Not Implemented", "Passphrase change functionality is not yet implemented.");
}

void Settings::onAuthCancelClicked()
{
    // Clear auth code input
    ui->authCodeInput->clear();
    
    // Navigate back to the previous window
    WindowManager::instance().showReceived();
}

void Settings::onAuthSaveClicked()
{
    QString auth_code = ui->authCodeInput->text().trimmed();
    
    if (auth_code.length() != 44) {
        StyledMessageBox::error(this, "Invalid Code", "The authentication code must be 44 characters long");
        return;
    }

    if (StyledMessageBox::confirmDialog(this, "Connection Request", 
        "A new device wants to connect.\n\nEnsure you trust this device before accepting.\n\nDo you wish to accept this connection?")) {
        
        std::vector<unsigned char> decoded_key = base642bin(auth_code.toStdString());
        if (decoded_key.size() != crypto_sign_PUBLICKEYBYTES) {
            StyledMessageBox::error(this, "Invalid Key", 
                "The authentication code contains an invalid public key.");
            return;
        }

        unsigned char pk_new_device[crypto_sign_PUBLICKEYBYTES];
        std::copy(decoded_key.begin(), decoded_key.end(), pk_new_device);
        
        try {
            add_trusted_device(pk_new_device);
            StyledMessageBox::success(this, "Connection Accepted", 
                "Connection request has been accepted.");
            qDebug() << "Connection accepted with public key:" << auth_code;
        } catch (const std::exception& e) {
            StyledMessageBox::error(this, "Connection Failed", 
                QString("Failed to add trusted device: %1").arg(e.what()));
        }
    } else {
        StyledMessageBox::info(this, "Connection Denied", 
            "Connection request has been denied.");
        qDebug() << "Connection denied";
    }
}

void Settings::onLogoutButtonClicked() {
    // TODO: Implement logout functionality
    StyledMessageBox::info(this, "Not Implemented", "Logout functionality is not yet implemented.");
}

void Settings::onScanQRButtonClicked()
{
    m_cameraFunctionality->showScanDialog();
}