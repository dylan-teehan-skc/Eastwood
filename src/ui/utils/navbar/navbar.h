#pragma once
#include <QWidget>
#include <QPushButton>

namespace Ui { class NavBar; }

class NavBar : public QWidget {
    Q_OBJECT
public:
    explicit NavBar(QWidget *parent = nullptr);
    ~NavBar();

    void setActiveButton(const QString& buttonName);

signals:
    void receivedClicked();
    void sentClicked();
    void sendFileClicked();
    void settingsClicked();
    void logoutClicked();

private slots:
    void onReceivedButtonClicked();
    void onSentButtonClicked();
    void onSendFileButtonClicked();
    void onSettingsButtonClicked();
    void onLogoutButtonClicked();

private:
    Ui::NavBar *ui;
    void setupConnections();

    static void updateButtonStyle(QPushButton* button, bool isActive);
};