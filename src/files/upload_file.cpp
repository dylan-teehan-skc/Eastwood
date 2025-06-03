#include "upload_file.h"

#include <QFile>
#include <vector>

#include "src/algorithms/algorithms.h"
#include "src/endpoints/endpoints.h"

std::string upload_file(const std::string &file_path) {
    QFile file(file_path.c_str());

    if (!file.open(QIODevice::ReadOnly)) {
        throw std::runtime_error("File " + file_path + " not found");
    }

    const QByteArray buff = file.readAll();
    file.close();

    const auto file_key = SecureMemoryBuffer::create(SYM_KEY_LEN);
    randombytes_buf(file_key->data(), SYM_KEY_LEN);

    unsigned char nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, CHA_CHA_NONCE_LEN);

    const auto encrypted_bytes = encrypt_bytes(buff, std::move(file_key), nonce);

    const std::string file_uuid = post_upload_file(encrypted_bytes);

    unsigned char file_key_nonce[CHA_CHA_NONCE_LEN];
    randombytes_buf(nonce, CHA_CHA_NONCE_LEN);
    randombytes_buf(file_key_nonce, CHA_CHA_NONCE_LEN);

    const auto encrypted_file_key = encrypt_symmetric_key(file_key, file_key_nonce);
    save_encrypted_file_key(file_uuid, encrypted_file_key, file_key_nonce);

    return file_uuid;
}
