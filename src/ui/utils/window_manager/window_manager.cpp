#include "window_manager.h"
#include "../../windows/received_dashboard/received_dash.h"
#include "../../windows/sent_dashboard/sent_dash.h"
#include "../../windows/send_file/send_file.h"
#include "../../windows/settings/settings.h"
#include "../../windows/login/login.h"
#include "../../windows/register/register.h"

WindowManager& WindowManager::instance()
{
    static WindowManager instance;
    return instance;
}

WindowManager::WindowManager()
    : m_received(nullptr)
    , m_sent(nullptr)
    , m_sendFile(nullptr)
    , m_settings(nullptr)
    , m_login(nullptr)
    , m_register(nullptr)
{
}

WindowManager::~WindowManager()
{
    cleanup();
}

void WindowManager::cleanup()
{
    deleteWindow(m_received);
    deleteWindow(m_sent);
    deleteWindow(m_sendFile);
    deleteWindow(m_settings);
    deleteWindow(m_login);
    deleteWindow(m_register);
    
    // Clean up any remaining windows in the list
    for (QWidget* window : m_windows) {
        if (window) {
            window->hide();
            window->deleteLater();
        }
    }
    m_windows.clear();
}

void WindowManager::showReceived()
{
    if (!m_received) {
        m_received = new Received();
        m_received->setAttribute(Qt::WA_DeleteOnClose);
        m_windows.append(m_received);
        connect(m_received, &Received::destroyed, this, [this]() {
            m_received = nullptr;
            m_windows.removeOne(m_received);
        });
    }
    m_received->show();
    emit windowShown("receivedButton");
}

void WindowManager::showSent()
{
    if (!m_sent) {
        m_sent = new Sent();
        m_sent->setAttribute(Qt::WA_DeleteOnClose);
        m_windows.append(m_sent);
        connect(m_sent, &Sent::destroyed, this, [this]() {
            m_sent = nullptr;
            m_windows.removeOne(m_sent);
        });
    }
    m_sent->show();
    emit windowShown("sentButton");
}

void WindowManager::showSendFile()
{
    if (!m_sendFile) {
        m_sendFile = new SendFile();
        m_sendFile->setAttribute(Qt::WA_DeleteOnClose);
        m_windows.append(m_sendFile);
        connect(m_sendFile, &SendFile::destroyed, this, [this]() {
            m_sendFile = nullptr;
            m_windows.removeOne(m_sendFile);
        });
    }
    m_sendFile->show();
    emit windowShown("sendFileButton");
}

void WindowManager::showSettings()
{
    if (!m_settings) {
        m_settings = new Settings();
        m_settings->setAttribute(Qt::WA_DeleteOnClose);
        m_windows.append(m_settings);
        connect(m_settings, &Settings::destroyed, this, [this]() {
            m_settings = nullptr;
            m_windows.removeOne(m_settings);
        });
    }
    m_settings->show();
    emit windowShown("settingsButton");
}

void WindowManager::showLogin()
{
    // Close all existing windows
    for (QWidget* window : m_windows) {
        window->close();
    }
    m_windows.clear();

    if (!m_login) {
        m_login = new Login();
        m_login->setAttribute(Qt::WA_DeleteOnClose);
        m_windows.append(m_login);
        connect(m_login, &Login::destroyed, this, [this]() {
            m_login = nullptr;
            m_windows.removeOne(m_login);
        });
    }
    m_login->show();
    emit windowShown("loginButton");
}

void WindowManager::showRegister()
{
    // Close all existing windows
    for (QWidget* window : m_windows) {
        window->close();
    }
    m_windows.clear();

    if (!m_register) {
        m_register = new Register();
        m_register->setAttribute(Qt::WA_DeleteOnClose);
        m_windows.append(m_register);
        connect(m_register, &Register::destroyed, this, [this]() {
            m_register = nullptr;
            m_windows.removeOne(m_register);
        });
    }
    m_register->show();
    emit windowShown("registerButton");
}