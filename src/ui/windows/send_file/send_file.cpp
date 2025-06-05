#include "send_file.h"
#include "ui_send_file.h"
#include <src/ui/utils/messagebox.h>
#include <src/ui/utils/window_manager/window_manager.h>
#include <src/ui/utils/navbar/navbar.h>
#include <QFileInfo>
#include <QFileDialog>
#include <QLineEdit>
#include <QCheckBox>

#include "src/communication/ReceiveFlow.h"
#include "src/communication/send_file_to/send_file_to.h"
#include "src/ui/utils/byte_converter/byte_converter.h"
#include "src/algorithms/constants.h"
#include "src/ui/utils/input_validation/name_validator.h"


SendFile::SendFile(QWidget *parent)
    : QWidget(parent)
      , ui(new Ui::SendFile) {
    ui->setupUi(this);
    setupConnections();
}

SendFile::~SendFile() {
    delete ui;
}

void SendFile::setupConnections() {
    connect(ui->browseButton, &QPushButton::clicked, this, &SendFile::onBrowseClicked);
    connect(ui->sendButton, &QPushButton::clicked, this, &SendFile::onSendClicked);
    connect(ui->showAuthCodeButton, &QPushButton::clicked, this, &SendFile::onShowAuthCodeClicked);

    // Connect NavBar signals
    if (NavBar *navbar = findChild<NavBar *>()) {
        connect(navbar, &NavBar::receivedClicked, this, &SendFile::onReceivedButtonClicked);
        connect(navbar, &NavBar::sentClicked, this, &SendFile::onSentButtonClicked);
        connect(navbar, &NavBar::settingsClicked, this, &SendFile::onSettingsButtonClicked);
        connect(navbar, &NavBar::sendFileClicked, this, &SendFile::onSendFileButtonClicked);
    }
}

void SendFile::onBrowseClicked() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File", "", "All Files (*.*)");
    if (!filePath.isEmpty()) {
        // Sanitize the file path
        QFileInfo fileInfo(filePath);
        QString canonicalPath = fileInfo.canonicalFilePath();

        // use canonical path to avoid path traversal attacks
        if (canonicalPath.isEmpty() || !fileInfo.exists()) {
            StyledMessageBox::error(this, "Invalid File",
                "The selected file path is invalid or does not exist.");
            return;
        }

        // Get file information
        qint64 size = fileInfo.size();

        if (size > MAX_FILE_SIZE_BYTES) {  // 250KB in bytes
            StyledMessageBox::error(this, "File Too Large",
                ("The selected file is too large. Maximum file size is " + convertFileSizeToHumanReadable(MAX_FILE_SIZE_BYTES)).data());
            return;
        }

        ui->filePathInput->setText(canonicalPath);
        QString fileName = fileInfo.fileName();

        // Convert size to human-readable format
        const QString sizeStr = QString::fromStdString(convertFileSizeToHumanReadable(size));
        // Format the details text
        QString details = QString("File Details:\n\n"
                    "Name: %1\n"
                    "Size: %2\n"
                    "Type: %3\n"
                    "Last Modified: %4")
                .arg(fileName)
                .arg(sizeStr)
                .arg(fileInfo.suffix().toUpper())
                .arg(fileInfo.lastModified().toString("yyyy-MM-dd hh:mm:ss"));

        ui->fileDetailsLabel->setText(details);
    }
}

// purple send button in send_file.ui
void SendFile::onSendClicked() {
    const QString filePath = ui->filePathInput->text();
    const QString username = ui->usernameInput->text();
    QString errorMessage;

    if (filePath.isEmpty()) {
        StyledMessageBox::warning(this, "No File Selected", "Please select a file to send.");
        return;
    }

    if (!NameValidator::validateUsername(username, errorMessage)) {
        StyledMessageBox::warning(this, "Invalid Username", errorMessage);
        return;
    }

    send_file_to(ui->usernameInput->text().toStdString(), ui->filePathInput->text().toStdString(), !already_fetched_bundles);

    StyledMessageBox::info(this, "File Sent", "File has been sent successfully!");
    already_fetched_bundles = false;
}

void SendFile::navigateTo(QWidget *newWindow) {
    newWindow->setParent(this->parentWidget()); // Set the same parent
    newWindow->show();
    this->setAttribute(Qt::WA_DeleteOnClose); // Mark for deletion when closed
    close(); // This will trigger deletion due to WA_DeleteOnClose
}

void SendFile::onReceivedButtonClicked() const {
    ui->usernameInput->clear();
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
    WindowManager::instance().showReceived();
}

void SendFile::onSentButtonClicked() const {
    ui->usernameInput->clear();
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
    WindowManager::instance().showSent();
}

void SendFile::onSendFileButtonClicked() const {
    ui->usernameInput->clear();
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
}

void SendFile::onSettingsButtonClicked() const {
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
    ui->usernameInput->clear();
    WindowManager::instance().showSettings();
}

void SendFile::onShowAuthCodeClicked()
{
    // fetch keybundles;
    update_handshakes();
    auto their_device_ids = RatchetSessionManager::instance().get_device_ids_of_existing_handshakes(ui->usernameInput->text().toStdString());
    auto bundles = get_keybundles(ui->usernameInput->text().toStdString(), their_device_ids);
    RatchetSessionManager::instance().create_ratchets_if_needed(ui->usernameInput->text().toStdString(), bundles);
    their_device_ids = RatchetSessionManager::instance().get_device_ids_of_existing_handshakes(ui->usernameInput->text().toStdString()); // update with  new

    already_fetched_bundles = true;

    auto my_device_pub = get_public_key("device");

    auto code = concat_ordered(reinterpret_cast<const unsigned char *>(my_device_pub.data()),my_device_pub.size(), their_device_ids[0].data(), their_device_ids[0].size());
    auto base_code = bin2base64(code.data(), code.size());

    QString authCode = QString::fromStdString(base_code); // TODO UPDATE THIS
    StyledMessageBox::displayCode(this, "Authentication Code", 

        "Please verify this code with the sender's device:", authCode);
}
