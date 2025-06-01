#include "salt.h"
#include <QDir>
#include <QStandardPaths>
#include <QString>

QString salt_path(const std::string &username) {
    const QString data_path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (!QDir().mkpath(data_path)) {
        throw std::runtime_error("Failed to open application directory");
    };
    // $APP_DIR/alice_salt.bin
    const QString file_path = data_path + "/" + QString(username.c_str()) + "_salt.bin";
    return file_path;
}

void get_salt_from_file(const std::string &username, unsigned char salt[crypto_pwhash_SALTBYTES]) {
    const QString file_path = salt_path(username);
    qDebug() << "Loading salt from file:" << file_path;
    QFile file(file_path);
    if (!file.open(QIODevice::ReadOnly)) {
        throw std::runtime_error("Failed to open file for reading:" + file.errorString().toStdString());
    }

    QDataStream stream(&file);
    stream.readRawData(reinterpret_cast<char *>(salt), crypto_pwhash_SALTBYTES);
    file.close();
}

void save_salt_to_file(const std::string &username, unsigned char salt[crypto_pwhash_SALTBYTES]) {
    const QString file_path = salt_path(username);
    qDebug() << "Saving salt to file:" << file_path;
    QFile file(file_path);
    if (!file.open(QIODevice::WriteOnly)) {
        throw std::runtime_error("Failed to open file for writing:" + file.errorString().toStdString());
    }
    QDataStream stream(&file);
    stream.writeRawData(reinterpret_cast<const char *>(salt), crypto_pwhash_SALTBYTES);
    file.close();
}
