#include <QFileInfo>
#include <QMimeDatabase>
#include <vector>
#include <nlohmann/json.hpp>

#include "src/algorithms/algorithms.h"
#include "src/endpoints/endpoints.h"
#include "src/key_exchange/XChaCha20-Poly1305.h"

std::string upload_file(const std::string &file_path, const std::unique_ptr<SecureMemoryBuffer> &file_key) {
    QFile file(file_path.c_str());

    if (!file.open(QIODevice::ReadOnly)) {
        throw std::runtime_error("File " + file_path + " not found");
    }

    // Get file metadata
    const QFileInfo fileInfo(file_path.c_str());
    const QMimeDatabase mimeDb;
    const QMimeType mimeType = mimeDb.mimeTypeForFile(fileInfo);

    const QByteArray buff = file.readAll();
    file.close();

    const json metadata = {
        {"name", fileInfo.fileName().toStdString()},
        {"size", fileInfo.size()},
        {"mime_type", mimeType.name().toStdString()},
    };
    const QByteArray metadataBytes = QByteArray::fromStdString(metadata.dump());
    const auto encrypted_metadata = encrypt_message_given_key(
        reinterpret_cast<const unsigned char *>(metadataBytes.data()), metadataBytes.size(), file_key->data());

    const auto encrypted_file_data = encrypt_message_given_key(reinterpret_cast<const unsigned char *>(buff.data()),
                                                               buff.size(), file_key->data());

    const std::string file_uuid = post_upload_file(encrypted_file_data, encrypted_metadata);
    return file_uuid;
}
