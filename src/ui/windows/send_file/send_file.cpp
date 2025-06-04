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
    std::map<std::array<unsigned char, 32>, std::tuple<std::array<unsigned char, 32>, MessageHeader>> keys_to_send_key = RatchetSessionManager::instance().get_keys_for_identity(ui->usernameInput->text().toStdString());

    if (keys_to_send_key.size() > 0) {
        std::vector<std::tuple<std::array<unsigned char,32>, DeviceMessage*>> messages;
        for (const auto& pair : keys_to_send_key) {
            const auto device_id = pair.first;
            const auto& [key, message_header] = pair.second;

            auto file_key = get_decrypted_file_key(uuid);
            std::cout << "key used to encrypt file "<< bin2hex(file_key->data(),32) << std::endl;
            auto message = new DeviceMessage();
            message->header = message_header;
            strncpy(message->header.file_uuid, uuid.c_str(), sizeof(message->header.file_uuid) - 1);
            message->header.file_uuid[sizeof(message->header.file_uuid) - 1] = '\0';

            // Encrypt the file key using the message key
            message->ciphertext = encrypt_message_given_key(file_key->data(), file_key->size(), key.data());

            messages.push_back(std::make_tuple(device_id, message));
        }
        post_ratchet_message(messages, SessionTokenManager::instance().getUsername());

        // Save sent messages to database (similar to received_dash.cpp)
        for (auto [device_id, msg] : messages) {
            // Get the file key that was encrypted in the message
            auto file_key = get_decrypted_file_key(uuid);
            
            // Re-encrypt the file key with a new symmetric key for database storage
            auto message_encryption_key = SecureMemoryBuffer::create(32);
            crypto_aead_chacha20poly1305_ietf_keygen(message_encryption_key->data());

            // Generate nonce for message encryption
            auto message_nonce = new unsigned char[CHA_CHA_NONCE_LEN];
            randombytes_buf(message_nonce, CHA_CHA_NONCE_LEN);

            // Copy the encryption key for saving BEFORE moving it
            auto sk_buffer = SecureMemoryBuffer::create(32);
            memcpy(sk_buffer->data(), message_encryption_key->data(), 32);

            // Encrypt the file key (which was the original "message" content)
            auto encrypted_message_again = encrypt_bytes(
                QByteArray(reinterpret_cast<const char*>(file_key->data()), file_key->size()), 
                std::move(message_encryption_key), 
                message_nonce
            );

            auto key_nonce = new unsigned char[CHA_CHA_NONCE_LEN];
            randombytes_buf(key_nonce, CHA_CHA_NONCE_LEN);

            auto encrypted_key = encrypt_symmetric_key(sk_buffer, key_nonce);
            
            // Extract file_uuid from header
            std::string file_uuid(msg->header.file_uuid);
            
            // Get current username and save the message
            std::string current_username = SessionTokenManager::instance().getUsername();
            
            // Save using current user as sender (since this is a sent message)
            save_message_and_key(current_username, device_id, file_uuid, encrypted_message_again, message_nonce, encrypted_key, key_nonce);
            
            // Clean up allocated arrays
            delete[] message_nonce;
            delete[] key_nonce;
        }

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
