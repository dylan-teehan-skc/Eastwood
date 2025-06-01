#include "./device_register.h"
#include "ui_device_register.h"
#include "src/ui/utils/window_manager/window_manager.h"
#include <iostream>
#include <QClipboard>
#include <QApplication>
#include "src/ui/utils/messagebox.h"

DeviceRegister::DeviceRegister(const std::string& auth_code, const QImage& qr_code, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::DeviceRegister)
    , m_auth_code(auth_code)
{
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
    WindowManager::instance().showRegister();
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
