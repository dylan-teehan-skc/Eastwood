#ifndef WINDOW_MANAGER_H
#define WINDOW_MANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QWidget>

// Forward declarations to reduce includes
class Received;
class Sent;
class SendFile;
class Settings;
class Login;
class Register;

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
    void deleteWindow(T*& window) {
        if (window) {
            window->hide();
            window->deleteLater();
            window = nullptr;
        }
    }

    Received* m_received;
    Sent* m_sent;
    SendFile* m_sendFile;
    Settings* m_settings;
    Login* m_login;
    Register* m_register;
    QList<QWidget*> m_windows;  // List to track all windows
};

#endif // WINDOW_MANAGER_H