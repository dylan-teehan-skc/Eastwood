#include "send_file.h"
#include "ui_send_file.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "../../utils/navbar/navbar.h"
#include <QFileInfo>
#include <QFileDialog>
#include <QLineEdit>
#include <QCheckBox>

#include "src/endpoints/endpoints.h"
#include "src/files/upload_file.h"
#include "src/keys/session_token_manager.h"
#include "src/key_exchange/utils.h"
#include "src/key_exchange/XChaCha20-Poly1305.h"
#include "src/sessions/RatchetSessionManager.h"
#include "src/sql/queries.h"

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
        ui->filePathInput->setText(filePath);

        // Get file information
        QFileInfo fileInfo(filePath);
        QString fileName = fileInfo.fileName();
        qint64 size = fileInfo.size();
        QString sizeStr;

        // Convert size to human-readable format
        if (size < 1024) {
            sizeStr = QString("%1 B").arg(size);
        } else if (size < 1024 * 1024) {
            sizeStr = QString("%1 KB").arg(size / 1024.0, 0, 'f', 1);
        } else if (size < 1024 * 1024 * 1024) {
            sizeStr = QString("%1 MB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
        } else {
            sizeStr = QString("%1 GB").arg(size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
        }

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
    if (filePath.isEmpty()) {
        StyledMessageBox::warning(this, "No File Selected", "Please select a file to send.");
        return;
    }

    std::string uuid = upload_file(filePath.toStdString());
    std::map<std::array<unsigned char, 32>, std::tuple<std::array<unsigned char, 32>, MessageHeader *>> keys_to_send_key = RatchetSessionManager::instance().get_keys_for_identity(ui->usernameInput->text().toStdString());

    if (keys_to_send_key.size() > 0) {
        std::vector<std::tuple<std::array<unsigned char,32>, DeviceMessage*>> messages;
        for (const auto& pair : keys_to_send_key) {
            const auto device_id = pair.first;
            const auto& [key, message_header] = pair.second;

            auto file_key = get_decrypted_file_key(uuid);
            std::cout << "key used to encrypt file "<< bin2hex(file_key->data(),32) << std::endl;
            auto message = new DeviceMessage();
            message->header = message_header;
            strncpy(message->header->file_uuid, uuid.c_str(), sizeof(message->header->file_uuid) - 1);
            message->header->file_uuid[sizeof(message->header->file_uuid) - 1] = '\0';

            // Encrypt the file key using the message key
            std::vector<unsigned char> encrypted_data = encrypt_message_given_key(file_key->data(), file_key->size(), key.data());
            message->length = encrypted_data.size();
            message->ciphertext = new unsigned char[message->length];
            memcpy(message->ciphertext, encrypted_data.data(), message->length);

            messages.push_back(std::make_tuple(device_id, message));
        }
        post_ratchet_message(messages, SessionTokenManager::instance().getUsername());

        // Clean up DeviceMessage objects after posting
        for (auto [device_id, msg] : messages) {
            delete msg;  // DeviceMessage destructor handles header and ciphertext cleanup
        }
    }

    StyledMessageBox::info(this, "File Sent", "File has been sent successfully!");
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
