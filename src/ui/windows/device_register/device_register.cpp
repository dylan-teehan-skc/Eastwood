#include "./device_register.h"
#include "ui_device_register.h"
#include "src/ui/utils/window_manager/window_manager.h"
#include <iostream>
#include <QClipboard>
#include <QApplication>
#include <thread>
#include <unistd.h>
#include <QDebug>
#include <QMetaObject>
#include <QCoreApplication>

#include "src/auth/login/login.h"
#include "src/endpoints/endpoints.h"
#include "src/ui/utils/messagebox.h"

void continuously_ping(std::array<unsigned char, 32> pk_device, DeviceRegister* deviceRegister) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        try {
            std::cout << "pinging" << std::endl;
            if (post_check_user_exists("dylanteehan123", pk_device.data())) {
                std::cout << "logged in" << std::endl;
                
                // Emit signal to main thread using QMetaObject::invokeMethod
                QMetaObject::invokeMethod(deviceRegister, "userRegistered", Qt::QueuedConnection);
                return; // Thread terminates here
            }
        } catch (const std::exception& e) {
            qDebug() << "Ping failed:" << e.what();
        }
    }
}

DeviceRegister::DeviceRegister(const std::string& auth_code, const QImage& qr_code, QWidget *parent, unsigned char* pk_device)
    : QWidget(parent)
    , ui(new Ui::DeviceRegister)
    , m_auth_code(auth_code)
{
    // Start the pinging thread if pk_device is provided
    if (pk_device) {
        std::array<unsigned char, 32> arr;
        std::memcpy(arr.data(), pk_device, 32);
        std::thread t1(continuously_ping, arr, this);
        t1.detach();
    }

    ui->setupUi(this);
    setupConnections();
    displayQRCode(qr_code);
    displayAuthCode(auth_code);
}

DeviceRegister::~DeviceRegister()
{
    delete ui;
}

void DeviceRegister::setupConnections()
{
    connect(ui->backButton, &QPushButton::clicked, this, &DeviceRegister::onBackButtonClicked);
    connect(ui->copyButton, &QPushButton::clicked, this, &DeviceRegister::onCopyButtonClicked);
    connect(this, &DeviceRegister::userRegistered, this, &DeviceRegister::onUserRegistered);
}

void DeviceRegister::displayQRCode(const QImage& qr_code)
{
    if (!qr_code.isNull()) {
        QPixmap pixmap = QPixmap::fromImage(qr_code);
        ui->qrCodeLabel->setPixmap(pixmap.scaled(200, 200, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    } else {
        std::cout << "QR code is null!" << std::endl;
    }
}

void DeviceRegister::displayAuthCode(const std::string& auth_code)
{
    int partLen = auth_code.length() / 4;
    QString code = QString::fromStdString(auth_code);
    ui->codeEdit1->setText(code.mid(0, partLen));
    ui->codeEdit2->setText(code.mid(partLen, partLen));
    ui->codeEdit3->setText(code.mid(2 * partLen, partLen));
    ui->codeEdit4->setText(code.mid(3 * partLen));
}

void DeviceRegister::onBackButtonClicked()
{
    WindowManager::instance().showLogin();
}

void DeviceRegister::onCopyButtonClicked()
{
    try {
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(QString::fromStdString(m_auth_code));
    StyledMessageBox::success(this, "Copied to Clipboard", "All codes have been successfully copied to your clipboard");
    } catch (const std::exception& e) {
        StyledMessageBox::error(this, "Copy Failed", "Failed to copy codes to clipboard");
    }
}

void DeviceRegister::onUserRegistered()
{
    try {
        login_user("dylanteehan123", std::make_unique<std::string>("slog"));
        WindowManager::instance().showReceived();
    } catch (const std::exception& e) {
        qDebug() << "Login failed:" << e.what();
    }
}
