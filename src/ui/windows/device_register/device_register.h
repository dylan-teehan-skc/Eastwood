#ifndef DEVICE_REGISTER_H
#define DEVICE_REGISTER_H

#include <QWidget>
#include <QImage>
#include <QClipboard>
#include <array>
#include <sodium.h>
#include "src/keys/secure_memory_buffer.h"
#include "src/algorithms/constants.h"

QT_BEGIN_NAMESPACE
namespace Ui { class DeviceRegister; }
QT_END_NAMESPACE

class DeviceRegister : public QWidget {
    Q_OBJECT

public:
    explicit DeviceRegister(const std::string& auth_code, const QImage& qr_code, QWidget *parent = nullptr, 
                          const unsigned char* pk_device = nullptr, std::unique_ptr<SecureMemoryBuffer> sk_device = nullptr,
                          const std::string& username = "");
    ~DeviceRegister() override;
    void displayQRCode(const QImage& qr_code) const;
    void displayAuthCode(const std::string& auth_code) const;

signals:
    void userRegistered(); // Signal emitted when background thread detects registration
    void pingTimeout(); // Signal emitted when pinging times out

private slots:
    static void onBackButtonClicked();
    void onCopyButtonClicked();
    void onUserRegistered();
    void onPingTimeout();

private:
    Ui::DeviceRegister *ui;
    std::string m_auth_code; // Store the full auth code
    std::string m_username;
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> m_pk_device;
    std::unique_ptr<SecureMemoryBuffer> m_sk_device;
    unsigned char m_nonce[CHA_CHA_NONCE_LEN];
    void setupConnections();
};

#endif // DEVICE_REGISTER_H
