#ifndef WINDOW_MANAGER_H
#define WINDOW_MANAGER_H

#include <QString>
#include <QList>
#include <QWidget>
#include <QPointer>
#include "src/keys/secure_memory_buffer.h"

// Forward declarations to reduce includes
class Received;
class Sent;
class SendFile;
class Settings;
class Login;
class Register;
class DeviceRegister;

class WindowManager : public QObject
{
    Q_OBJECT

public:
    static WindowManager& instance();

    // Window management methods
    void showReceived();
    void showSent();
    void showSendFile();
    void showSettings();
    void showLogin();
    void showRegister();
    void showDeviceRegister(const std::string& auth_code, const QImage& qr_code, 
                           unsigned char* pk_dev, std::unique_ptr<SecureMemoryBuffer> sk_dev,
                           const std::string& username);
    void cleanup();

signals:
    void windowShown(const QString& windowName);

protected:
    WindowManager();
    ~WindowManager() override;

private:
    // Prevent copying
    WindowManager(const WindowManager&) = delete;
    WindowManager& operator=(const WindowManager&) = delete;

    // Template helper methods
    template<typename T>
    static void deleteWindow(QPointer<T>& window) {
        if (!window.isNull()) {
            window->hide();
            window->deleteLater();
            window = nullptr;
        }
    }

    template<typename T, typename... Args>
    void showWindow(QPointer<T>& windowPtr, const QString& buttonName, Args&&... args);

    // Window pointers
    QPointer<Received> m_received;
    QPointer<Sent> m_sent;
    QPointer<SendFile> m_sendFile;
    QPointer<Settings> m_settings;
    QPointer<Login> m_login;
    QPointer<Register> m_register;
    QPointer<DeviceRegister> m_deviceRegister;
    QList<QPointer<QWidget>> m_windows;
};

#endif // WINDOW_MANAGER_H