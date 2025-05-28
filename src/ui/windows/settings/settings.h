#ifndef SETTINGS_H
#define SETTINGS_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>

QT_BEGIN_NAMESPACE
namespace Ui { class Settings; }
QT_END_NAMESPACE

class Settings : public QWidget {
    Q_OBJECT

public:
    explicit Settings(QWidget *parent = nullptr);
    ~Settings() override;

private slots:
    void onWindowShown(const QString& windowName);
    void onReceivedButtonClicked();
    void onSentButtonClicked();
    void onSendFileButtonClicked();
    void onLogoutButtonClicked();
    void validatePassphrase();
    void onCancelClicked();
    void onSettingsButtonClicked();

private:
    Ui::Settings *ui;
    void setupConnections();
    void navigateTo(QWidget* newWindow);
};

#endif // SETTINGS_H