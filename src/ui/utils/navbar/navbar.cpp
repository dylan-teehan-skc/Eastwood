#include "navbar.h"
#include "ui_navbar.h"
#include "../../utils/window_manager/window_manager.h"
#include "../../utils/messagebox.h"

NavBar::NavBar(QWidget *parent) : QWidget(parent), ui(new Ui::NavBar) {
    ui->setupUi(this);
    setupConnections();
    // Set initial active button
    setActiveButton("receivedButton");
}

NavBar::~NavBar() { delete ui; }

void NavBar::setupConnections() {
    connect(ui->receivedButton, &QPushButton::clicked, this, &NavBar::receivedClicked);
    connect(ui->sentButton, &QPushButton::clicked, this, &NavBar::sentClicked);
    connect(ui->sendFileButton, &QPushButton::clicked, this, &NavBar::sendFileClicked);
    connect(ui->settingsButton, &QPushButton::clicked, this, &NavBar::settingsClicked);
    connect(ui->logoutButton, &QPushButton::clicked, this, &NavBar::logoutClicked);
}

void NavBar::setActiveButton(const QString& buttonName) {
    // Reset all buttons to inactive state
    updateButtonStyle(ui->receivedButton, false);
    updateButtonStyle(ui->sentButton, false);
    updateButtonStyle(ui->sendFileButton, false);
    updateButtonStyle(ui->settingsButton, false);

    // Set the active button
    if (buttonName == "receivedButton") {
        updateButtonStyle(ui->receivedButton, true);
    } else if (buttonName == "sentButton") {
        updateButtonStyle(ui->sentButton, true);
    } else if (buttonName == "sendFileButton") {
        updateButtonStyle(ui->sendFileButton, true);
    } else if (buttonName == "settingsButton") {
        updateButtonStyle(ui->settingsButton, true);
    }
}

void NavBar::updateButtonStyle(QPushButton* button, bool isActive) {
    if (isActive) {
        button->setStyleSheet(R"(
            QPushButton {
                font-size: 14px;
                font-weight: 500;
                color: #6c5ce7;
                background-color: #f0eeff;
                border-radius: 8px;
                text-align: left;
                padding-left: 15px;
                border: 1px solid #e6e3ff;
            }
            QPushButton:hover {
                background-color: #e6e3ff;
                border-color: #dcd8ff;
            }
            QPushButton:pressed {
                background-color: #dcd8ff;
                border-color: #6c5ce7;
            }
        )");
    } else {
        button->setStyleSheet(R"(
            QPushButton {
                font-size: 14px;
                color: #636e72;
                background-color: transparent;
                border-radius: 8px;
                text-align: left;
                padding-left: 15px;
                border: 1px solid #f1f2f6;
            }
            QPushButton:hover {
                background-color: #f8f9fa;
                color: #2d3436;
                border-color: #e9ecef;
            }
            QPushButton:pressed {
                background-color: #f1f2f6;
                color: #2d3436;
                border-color: #dfe6e9;
            }
        )");
    }
}

void NavBar::onReceivedButtonClicked() {
    WindowManager::instance().showReceived();
    setActiveButton("receivedButton");
    hide();
}

void NavBar::onSentButtonClicked() {
    WindowManager::instance().showSent();
    setActiveButton("sentButton");
    hide();
}

void NavBar::onSendFileButtonClicked() {
    WindowManager::instance().showSendFile();
    setActiveButton("sendFileButton");
    hide();
}

void NavBar::onSettingsButtonClicked() {
    WindowManager::instance().showSettings();
    setActiveButton("settingsButton");
    hide();
}

void NavBar::onLogoutButtonClicked() {
    // TODO: Implement logout functionality
    // - Show confirmation dialog
    // - Clear sensitive data
    // - Close all windows
    // - Return to login screen
    StyledMessageBox::info(this, "Not Implemented", "Logout functionality is not yet implemented.");
}
