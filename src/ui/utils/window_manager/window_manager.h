#ifndef WINDOW_MANAGER_H
#define WINDOW_MANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QWidget>
#include <QPointer>

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

    void showReceived();
    void showSent();
    void showSendFile();
    void showSettings();
    void showLogin();
    void showRegister();
    void showDeviceRegister(const std::string& auth_code, const QImage& qr_code);
    void cleanup();

signals:
    void windowShown(const QString& windowName);

protected:
    WindowManager();
    virtual ~WindowManager();

private:
    // Delete copy constructor and assignment operator
    WindowManager(const WindowManager&) = delete;
    WindowManager& operator=(const WindowManager&) = delete;

    // Template function to handle different window types
    template<typename T>
    void deleteWindow(QPointer<T>& window) {
        if (!window.isNull()) {
            window->hide();
            window->deleteLater();
            window = nullptr;
        }
    }

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