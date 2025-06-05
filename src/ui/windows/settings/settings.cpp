#include "settings.h"
#include "ui_settings.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "../../utils/navbar/navbar.h"
#include "src/key_exchange/utils.h"
#include "src/auth/register_device/register_device.h"
#include <QVBoxLayout>
#include <QFileDialog>
#include <QLineEdit>
#include <QTimer>
#include <QCheckBox>
#include <QImageReader>
#include <QPixmap>
#include <QLabel>
#include <QDebug>
#include <QPainter>
#include <QIcon>
#include <cstring>

#include "src/auth/logout.h"
#include "src/auth/rotate_master_key/rotate_master_key.h"
#include "src/endpoints/endpoints.h"
#include "src/keys/session_token_manager.h"

Settings::Settings(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Settings)
    , m_cameraFunctionality(new CameraFunctionality(this))
    , m_refreshSpinnerTimer(new QTimer(this))
    , m_spinnerAngle(0)
{
    ui->setupUi(this);
    setupConnections();

    // Setup refresh spinner timer
    connect(m_refreshSpinnerTimer, &QTimer::timeout, this, &Settings::handleRefreshSpinner);

    // Update username from KEK manager
    updateUsername();
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
    connect(ui->authSaveButton, &QPushButton::clicked, this, &Settings::onAuthVerifyClicked);
    connect(ui->refreshDevicesButton, &QPushButton::clicked, this, &Settings::onRefreshDevicesClicked);

    // Connect NavBar signals
    if (NavBar* navbar = findChild<NavBar*>()) {
        connect(navbar, &NavBar::receivedClicked, this, &Settings::onReceivedButtonClicked);
        connect(navbar, &NavBar::sentClicked, this, &Settings::onSentButtonClicked);
        connect(navbar, &NavBar::sendFileClicked, this, &Settings::onSendFileButtonClicked);
        connect(navbar, &NavBar::settingsClicked, this, &Settings::onSettingsButtonClicked);
        connect(navbar, &NavBar::logoutClicked, this, &Settings::onLogoutButtonClicked);
    }
    connect(ui->scanQRButton, &QPushButton::clicked, this, &Settings::onScanQRButtonClicked);

    // Initial device list update
    updateDeviceList();
}

void Settings::validatePassphrase() const {
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

void Settings::onReceivedButtonClicked() const {
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showReceived();
}

void Settings::onSentButtonClicked() const {
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showSent();
}

void Settings::onSendFileButtonClicked() const {
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showSendFile();
}

void Settings::onSettingsButtonClicked() const {
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
}

void Settings::onPassphraseCancelClicked() const {
    // Clear all passphrase fields
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();

    // Navigate back to the previous window
    WindowManager::instance().showReceived();
}

void Settings::onPassphraseSaveClicked() {
    validatePassphrase();
    const auto old_password = ui->currentPassphrase->text().toStdString();
    const auto new_password = ui->newPassphrase->text().toStdString();
    try {
        auto old_password_buffer = SecureMemoryBuffer::create(old_password.size());
        auto new_password_buffer = SecureMemoryBuffer::create(new_password.size());
        
        // Copy the passwords into the secure buffers
        std::memcpy(old_password_buffer->data(), old_password.data(), old_password.size());
        std::memcpy(new_password_buffer->data(), new_password.data(), new_password.size());
        
        rotate_master_password(Database::get().get_username(), std::move(old_password_buffer), std::move(new_password_buffer));
    } catch (std::runtime_error &e) {
        StyledMessageBox::error(
            this, "Invalid password", "Invalid password");
        return;
    }
    StyledMessageBox::info(this, "Password Updated", "Your password was updated");

    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
}

void Settings::onAuthCancelClicked() const {
    // Clear auth code input
    ui->authCodeInput->clear();

    // Navigate back to the previous window
    WindowManager::instance().showReceived();
}

void Settings::onAuthVerifyClicked()
{
    QString auth_code = ui->authCodeInput->text().trimmed();

    if (auth_code.length() != 44) {
        StyledMessageBox::error(this, "Invalid Code", "The authentication code must be 44 characters long");
        return;
    }

    handleDeviceConnection(auth_code);
}

bool Settings::handleDeviceConnection(const QString& publicKey)
{
    QString deviceName;
    if (StyledMessageBox::connectionRequest(this, "Connection Request",
        "A new device wants to connect.\n\nEnsure you trust this device before accepting.\n\nDo you wish to accept this connection?",
        deviceName)) {

        try {
            unsigned char pk_new_device[crypto_sign_PUBLICKEYBYTES];
            size_t bin_len;
            if (sodium_base642bin(pk_new_device, crypto_sign_PUBLICKEYBYTES,
                                publicKey.toStdString().c_str(), publicKey.length(),
                                nullptr, &bin_len, nullptr,
                                sodium_base64_VARIANT_ORIGINAL) != 0) {
                StyledMessageBox::error(this, "Invalid Key",
                    "The authentication code contains an invalid public key.");
                return false;
            }
            if (bin_len != crypto_sign_PUBLICKEYBYTES) {
                StyledMessageBox::error(this, "Invalid Key",
                    "The authentication code contains an invalid public key.");
                return false;
            }

            add_trusted_device(pk_new_device, deviceName.toStdString());
            StyledMessageBox::success(this, "Connection Accepted",
            QString("Connection request has been accepted for device: %1").arg(deviceName));
            updateDeviceList();
            qDebug() << "Connection accepted with public key:" << publicKey << "and device name:" << deviceName;
            return true;
        } catch (const std::runtime_error& e) {
            StyledMessageBox::error(this, "Connection Failed",
                QString("Failed to add trusted device: %1").arg(e.what()));
            qDebug() << "Connection failed:" << e.what();
        } catch (const std::exception& e) {
            StyledMessageBox::error(this, "Connection Failed",
                QString("An unexpected error occurred: %1").arg(e.what()));
            qDebug() << "Unexpected error:" << e.what();
        }
    } else {
        StyledMessageBox::info(this, "Connection Denied",
            "Connection request has been denied.");
        qDebug() << "Connection denied";
    }
    return false;
}

void Settings::onScanQRButtonClicked() const
{
    m_cameraFunctionality->showScanDialog();
}

void Settings::createDeviceBox(const std::string& deviceName) const {
    QWidget* deviceBox = new QWidget();
    deviceBox->setStyleSheet(R"(
        QWidget {
            background-color: white;
            border: 1px solid #dfe6e9;
            border-radius: 6px;
            padding: 8px;
        }
    )");

    QHBoxLayout* layout = new QHBoxLayout(deviceBox);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(8);

    QLabel* deviceLabel = new QLabel(QString::fromStdString(deviceName));
    deviceLabel->setStyleSheet("font-size: 14px; color: #2d3436;");
    layout->addWidget(deviceLabel);

    ui->deviceListWidgetLayout->addWidget(deviceBox);
}

void Settings::updateDeviceList()
{
    // Clear existing device boxes
    QLayoutItem* item;
    while ((item = ui->deviceListWidgetLayout->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }

    // Get and display devices
    std::vector<std::string> devices = get_devices();
    qDebug() << "Number of devices received:" << devices.size();
    qDebug() << "Devices:";
    for (const auto& device : devices) {
        qDebug() << "Device:" << QString::fromStdString(device);
        createDeviceBox(device);
    }

    // Add a spacer at the bottom
    ui->deviceListWidgetLayout->addStretch();
}

void Settings::handleRefreshSpinner()
{
    m_spinnerAngle = (m_spinnerAngle + 30) % 360;

    // Update the button's icon with the new angle
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.translate(8, 8);
    painter.rotate(m_spinnerAngle);
    painter.setPen(QPen(QColor("#6c5ce7"), 2));
    painter.drawLine(0, -6, 0, 6);
    painter.drawLine(-6, 0, 6, 0);
    ui->refreshDevicesButton->setIcon(QIcon(pixmap));
    ui->refreshDevicesButton->setIconSize(QSize(16, 16));
}

void Settings::onRefreshDevicesClicked()
{
    // Start the spinner animation
    m_spinnerAngle = 0;
    m_refreshSpinnerTimer->start(50); // Update every 50ms

    // Update the device list
    updateDeviceList();

    // Stop the spinner after 1 second
    QTimer::singleShot(1000, [this]() {
        m_refreshSpinnerTimer->stop();
        ui->refreshDevicesButton->setIcon(QIcon());
    });
}

void Settings::onLogoutButtonClicked() {
    logout();
    // Show login window
    WindowManager::instance().showLogin();
}

void Settings::updateUsername()
{
    auto username = SessionTokenManager::instance().getUsername();
    ui->usernameLabel->setText(QString("Username: %1").arg(QString::fromStdString(username)));
}