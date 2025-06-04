//
// Created by Josh Sloggett on 04/06/2025.
//

#ifndef RECEIVEFLOW_H
#define RECEIVEFLOW_H
#include <nlohmann/detail/input/parser.hpp>

#include "src/client_api_interactions/MakeAuthReq.h"
#include "src/endpoints/endpoints.h"
#include "src/key_exchange/XChaCha20-Poly1305.h"
#include "src/sessions/RatchetSessionManager.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>

inline void update_handshakes() {
    auto handshakes = get_handshake_backlog();

    for (auto &[username, keybundle] : handshakes) {
        RatchetSessionManager::instance().create_ratchets_if_needed(username, {keybundle});
    }
}

inline void update_messages() {
    auto messages = get_messages();
    std::cout << "DEBUG: update_messages() - Processing " << messages.size() << " messages" << std::endl;

    for (auto &[username, message] : messages) {
        std::cout << "\n--- DEBUG: Processing message for user: " << username << " ---" << std::endl;
        std::cout << "File UUID: " << std::string(message.header.file_uuid) << std::endl;
        std::cout << "Original ciphertext size: " << message.ciphertext.size() << " bytes" << std::endl;
        
        // Print first 16 bytes of original ciphertext
        std::cout << "Original ciphertext first 16 bytes: ";
        for (size_t i = 0; i < std::min((size_t)16, message.ciphertext.size()); i++) {
            printf("%02x ", message.ciphertext[i]);
        }
        std::cout << std::endl;
        
        auto key = RatchetSessionManager::instance().get_key_for_device(username, message.header);
        auto decrypted_message = decrypt_message_given_key(message.ciphertext.data(), message.ciphertext.size(), key.data());
        
        std::cout << "Decrypted message size: " << decrypted_message.size() << " bytes" << std::endl;
        std::cout << "Decrypted message (file key) first 8 bytes: ";
        for (size_t i = 0; i < std::min((size_t)8, decrypted_message.size()); i++) {
            printf("%02x ", decrypted_message[i]);
        }
        std::cout << std::endl;
        
        QByteArray q_decrypted_message(reinterpret_cast<const char*>(decrypted_message.data()), static_cast<int>(decrypted_message.size()));

        // re encrypt with new key
        std::unique_ptr<SecureMemoryBuffer> new_db_message_key = SecureMemoryBuffer::create(32);
        crypto_stream_xchacha20_keygen(new_db_message_key->data());

        std::array<unsigned char, CHA_CHA_NONCE_LEN> nonce_for_msg{};
        randombytes_buf(nonce_for_msg.data(), CHA_CHA_NONCE_LEN);

        auto encrypted_message_for_db = encrypt_bytes(q_decrypted_message, new_db_message_key, nonce_for_msg.data());
        
        std::cout << "Re-encrypted message for DB size: " << encrypted_message_for_db.size() << " bytes" << std::endl;
        std::cout << "Re-encrypted message first 16 bytes: ";
        for (size_t i = 0; i < std::min((size_t)16, encrypted_message_for_db.size()); i++) {
            printf("%02x ", encrypted_message_for_db[i]);
        }
        std::cout << std::endl;

        std::array<unsigned char, CHA_CHA_NONCE_LEN> nonce_for_key{};
        randombytes_buf(nonce_for_key.data(), CHA_CHA_NONCE_LEN);
        auto encrypted_key = encrypt_symmetric_key(new_db_message_key, nonce_for_key.data());

        // save to db
        std::cout << "Saving to database..." << std::endl;
        save_message_and_key(username, message.header.device_id, message.header.file_uuid, encrypted_message_for_db, nonce_for_msg.data(), encrypted_key, nonce_for_key.data());
        std::cout << "Successfully saved to database" << std::endl;
    }
}

// vector of file name, file size, mime type, uuid, username
inline std::vector<std::tuple<std::string, int, std::string, std::string, std::string>> get_file_metadata() {
    auto uuids = get_all_received_file_uuids();
    auto encrypted_metadata = get_encrypted_file_metadata(uuids);

    std::vector<std::tuple<std::string, int, std::string, std::string, std::string>> file_metadata;
    for (auto &[uuid, tuple] : encrypted_metadata) {
        auto [username, ciphertext] = tuple;
        std::cout << "\n--- Processing UUID: " << uuid << " ---" << std::endl;
        std::cout << "UUID from server: " << uuid << std::endl;
        std::cout << "Encrypted metadata size: " << ciphertext.size() << " bytes" << std::endl;
        
        // Check if this UUID exists in our database
        try {
            std::cout << "Checking if UUID " << uuid << " exists in our received_messages table..." << std::endl;
            auto key = get_decrypted_message(uuid);
            std::cout << "✓ UUID found in database" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "✗ UUID NOT found in database: " << e.what() << std::endl;
            std::cout << "This means we have metadata from server but no corresponding message in DB!" << std::endl;
            continue;
        }
        
        try {
            // For received files, the file key is stored as message content
            std::cout << "Attempting to get decrypted message (file key)..." << std::endl;
            auto key = get_decrypted_message(uuid);
            
            if (key.empty()) {
                std::cerr << "ERROR: Empty decrypted key for UUID " << uuid << std::endl;
                continue;
            }
            
            std::cout << "Successfully got file key, size: " << key.size() << " bytes" << std::endl;
            if (key.size() >= 8) {
                std::cout << "Key first 8 bytes: ";
                for (int i = 0; i < 8; i++) {
                    printf("%02x ", key[i]);
                }
                std::cout << std::endl;
            }
            
            std::cout << "Attempting to decrypt metadata..." << std::endl;
            auto decrypted_metadata = decrypt_message_given_key(ciphertext.data(), ciphertext.size(), key.data());
            
            if (decrypted_metadata.empty()) {
                std::cerr << "ERROR: Empty decrypted metadata for UUID " << uuid << std::endl;
                std::cerr << "Ciphertext size: " << ciphertext.size() << ", Key size: " << key.size() << std::endl;
                continue;
            }
            
            std::cout << "Successfully decrypted metadata, size: " << decrypted_metadata.size() << " bytes" << std::endl;
            
            // Convert to string and check if it's valid
            std::string metadata_str(decrypted_metadata.begin(), decrypted_metadata.end());
            if (metadata_str.empty()) {
                std::cerr << "ERROR: Empty metadata string for UUID " << uuid << std::endl;
                continue;
            }
            
            std::cout << "Attempting to parse JSON for UUID " << uuid << ": " << metadata_str << std::endl;
            
            auto metadata = json::parse(metadata_str);
            
            if (!metadata.contains("name") || !metadata.contains("size") || !metadata.contains("mime_type")) {
                std::cerr << "ERROR: Missing required fields in metadata for UUID " << uuid << std::endl;
                std::cout << "Available fields: ";
                for (auto& [key, value] : metadata.items()) {
                    std::cout << key << " ";
                }
                std::cout << std::endl;
                continue;
            }

            std::cout << "Successfully parsed metadata JSON" << std::endl;
            file_metadata.emplace_back(std::make_tuple(
                metadata["name"].get<std::string>(), 
                metadata["size"].get<int>(), 
                metadata["mime_type"].get<std::string>(),
                uuid,
                username
            ));
        } catch (const std::exception& e) {
            std::cerr << "ERROR processing metadata for UUID " << uuid << ": " << e.what() << std::endl;
            continue;
        }
    }

    std::cout << "Final result: " << file_metadata.size() << " successfully processed files" << std::endl;
    return file_metadata;
}

inline QString getFileFilterFromMimeType(const std::string& mime_type) {
    if (mime_type.empty()) {
        return "All Files (*.*)";
    }
    
    if (mime_type == "text/plain") {
        return "Text Files (*.txt);;All Files (*.*)";
    } else if (mime_type == "application/pdf") {
        return "PDF Files (*.pdf);;All Files (*.*)";
    } else if (mime_type == "image/jpeg") {
        return "JPEG Images (*.jpg *.jpeg);;All Files (*.*)";
    } else if (mime_type == "image/png") {
        return "PNG Images (*.png);;All Files (*.*)";
    } else if (mime_type == "image/gif") {
        return "GIF Images (*.gif);;All Files (*.*)";
    } else if (mime_type == "image/webp") {
        return "WebP Images (*.webp);;All Files (*.*)";
    } else if (mime_type == "video/mp4") {
        return "MP4 Videos (*.mp4);;All Files (*.*)";
    } else if (mime_type == "video/avi") {
        return "AVI Videos (*.avi);;All Files (*.*)";
    } else if (mime_type == "audio/mp3" || mime_type == "audio/mpeg") {
        return "MP3 Audio (*.mp3);;All Files (*.*)";
    } else if (mime_type == "audio/wav") {
        return "WAV Audio (*.wav);;All Files (*.*)";
    } else if (mime_type == "application/zip") {
        return "ZIP Archives (*.zip);;All Files (*.*)";
    } else if (mime_type == "application/x-rar-compressed") {
        return "RAR Archives (*.rar);;All Files (*.*)";
    } else if (mime_type == "application/msword") {
        return "Word Documents (*.doc);;All Files (*.*)";
    } else if (mime_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
        return "Word Documents (*.docx);;All Files (*.*)";
    } else if (mime_type == "application/vnd.ms-excel") {
        return "Excel Spreadsheets (*.xls);;All Files (*.*)";
    } else if (mime_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") {
        return "Excel Spreadsheets (*.xlsx);;All Files (*.*)";
    } else if (mime_type.substr(0, 5) == "text/") {
        return "Text Files (*.txt);;All Files (*.*)";
    } else if (mime_type.substr(0, 6) == "image/") {
        return "Image Files (*.jpg *.jpeg *.png *.gif *.bmp *.webp);;All Files (*.*)";
    } else if (mime_type.substr(0, 6) == "video/") {
        return "Video Files (*.mp4 *.avi *.mov *.mkv *.wmv);;All Files (*.*)";
    } else if (mime_type.substr(0, 6) == "audio/") {
        return "Audio Files (*.mp3 *.wav *.ogg *.flac *.aac);;All Files (*.*)";
    } else {
        // For unknown mime types, show a generic filter with the mime type info
        return QString("Files (%1) (*.*);;All Files (*.*)")
               .arg(QString::fromStdString(mime_type));
    }
}

inline void download_file(const std::string& file_uuid, std::string mime_type, std::string file_name, QWidget* parent = nullptr) {
    try {
        auto file_key = get_decrypted_message(file_uuid);
        
        if (file_key.empty()) {
            QMessageBox::critical(parent, "Download Error", "File key not found in database. Cannot decrypt file.");
            return;
        }

        auto encrypted_file_data = get_encrypted_file(file_uuid);
        
        if (encrypted_file_data.empty()) {
            QMessageBox::critical(parent, "Download Error", "Failed to download file from server or file is empty.");
            return;
        }

        QByteArray encrypted_data(reinterpret_cast<const char*>(encrypted_file_data.data()), 
                                  static_cast<int>(encrypted_file_data.size()));
        

        auto decrypted_data = decrypt_message_given_key(encrypted_file_data.data(), 
                                                        encrypted_file_data.size(), 
                                                        file_key.data());
        
        if (decrypted_data.empty()) {
            QMessageBox::critical(parent, "Download Error", "Failed to decrypt file. The file key may be incorrect.");
            return;
        }

        QString fileName = QFileDialog::getSaveFileName(
            parent,
            "Save Downloaded File",
            QString::fromStdString(file_name),
            getFileFilterFromMimeType(mime_type)
        );
        
        if (fileName.isEmpty()) {
            std::cout << "User cancelled save dialog" << std::endl;
            return;
        }
        
        QFile outputFile(fileName);
        if (!outputFile.open(QIODevice::WriteOnly)) {
            QMessageBox::critical(parent, "Save Error", 
                                QString("Failed to open file for writing: %1").arg(fileName));
            return;
        }
        
        qint64 bytesWritten = outputFile.write(reinterpret_cast<const char*>(decrypted_data.data()), 
                                              static_cast<qint64>(decrypted_data.size()));
        outputFile.close();
        
        if (bytesWritten != static_cast<qint64>(decrypted_data.size())) {
            QMessageBox::critical(parent, "Save Error", 
                                QString("Failed to write complete file. Expected %1 bytes, wrote %2 bytes.")
                                .arg(decrypted_data.size()).arg(bytesWritten));
            return;
        }
        
        std::cout << "Successfully saved file to: " << fileName.toStdString() << std::endl;
        QMessageBox::information(parent, "Download Complete", 
                               QString("File successfully downloaded and saved to:\n%1\n\nFile size: %2 bytes")
                               .arg(fileName).arg(decrypted_data.size()));
        
    } catch (const std::exception& e) {
        std::cerr << "Error downloading file: " << e.what() << std::endl;
        QMessageBox::critical(parent, "Download Error", 
                            QString("An error occurred while downloading the file:\n%1").arg(e.what()));
    }
}

#endif //RECEIVEFLOW_H
