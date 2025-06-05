#include "window_manager.h"
#include "../../windows/received_dashboard/received_dash.h"
#include "../../windows/sent_dashboard/sent_dash.h"
#include "../../windows/send_file/send_file.h"
#include "../../windows/settings/settings.h"
#include "../../windows/login/login.h"
#include "../../windows/register/register.h"
#include "../../windows/device_register/device_register.h"
#include "src/endpoints/endpoints.h"
#include <QDebug>

WindowManager &WindowManager::instance() {
    static WindowManager instance;
    return instance;
}

WindowManager::WindowManager() {
}

WindowManager::~WindowManager() {
    cleanup();
}

void WindowManager::cleanup() {
    auto disconnectIfValid = [this](const QObject *obj) {
        if (obj)
            disconnect(obj, nullptr, this, nullptr);
    };

    disconnectIfValid(m_received);
    disconnectIfValid(m_sent);
    disconnectIfValid(m_sendFile);
    disconnectIfValid(m_settings);
    disconnectIfValid(m_login);
    disconnectIfValid(m_register);
    disconnectIfValid(m_deviceRegister);

    // Close and cleanup all windows
    deleteWindow(m_received);
    deleteWindow(m_sent);
    deleteWindow(m_sendFile);
    deleteWindow(m_settings);
    deleteWindow(m_login);
    deleteWindow(m_register);
    deleteWindow(m_deviceRegister);

    // Clear the windows list
    m_windows.clear();
}

void WindowManager::restart() {
    qDebug() << "Restarting window manager";
    cleanup();
    showLogin();
}

template<typename T, typename... Args>
void WindowManager::showWindow(QPointer<T> &windowPtr, const QString &buttonName, Args &&... args) {
    // If window exists and is visible, just return
    if (!windowPtr.isNull() && windowPtr->isVisible()) {
        return;
    }

    // Hide all other windows first
    for (const QPointer<QWidget> &window: m_windows) {
        if (!window.isNull() && window != windowPtr) {
            window->hide();
        }
    }

    // Create new window if needed
    if (windowPtr.isNull()) {
        auto uniqueWindow = std::make_unique<T>(std::forward<Args>(args)...);
        uniqueWindow->setAttribute(Qt::WA_DeleteOnClose);
        windowPtr = uniqueWindow.get();

        // Cast to QWidget pointer before appending
        QPointer<QWidget> widgetPtr = qobject_cast<QWidget*>(windowPtr.data());
        m_windows.append(widgetPtr);

        // No need for connection - QPointer auto-nullifies
        uniqueWindow.release();
    }

    windowPtr->show();
    emit windowShown(buttonName);
}

void WindowManager::showReceived() {
    showWindow(m_received, "receivedButton");
}

void WindowManager::showSent() {
    showWindow(m_sent, "sentButton");
}

void WindowManager::showSendFile() {
    showWindow(m_sendFile, "sendFileButton");
}

void WindowManager::showSettings() {
    showWindow(m_settings, "settingsButton");
}

void WindowManager::showLogin() {
    showWindow(m_login, "loginButton");
}

void WindowManager::showRegister() {
    showWindow(m_register, "registerButton");
}

void WindowManager::showDeviceRegister(const std::string &auth_code, const QImage &qr_code,
                                       unsigned char *pk_dev, std::unique_ptr<SecureMemoryBuffer> sk_dev,
                                       const std::string &username) {
    showWindow(m_deviceRegister, "deviceRegisterButton", auth_code, qr_code, nullptr, pk_dev, std::move(sk_dev),
               username);
}
