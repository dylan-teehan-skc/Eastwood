#ifndef SETTINGS_H
#define SETTINGS_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include "src/ui/utils/camera_functionality/camera_functionality.h"
#include <QTimer>

QT_BEGIN_NAMESPACE
namespace Ui { class Settings; }
QT_END_NAMESPACE

class Settings : public QWidget {
    Q_OBJECT

public:
    explicit Settings(QWidget *parent = nullptr);
    ~Settings() override;

private slots:
    void onWindowShown(const QString& windowName) const;
    void onReceivedButtonClicked();
    void onSentButtonClicked();
    void onSendFileButtonClicked();
    void validatePassphrase();
    void onPassphraseCancelClicked();
    void onPassphraseSaveClicked();
    void onAuthCancelClicked();
    void onAuthVerifyClicked();
    void onSettingsButtonClicked();
    void onScanQRButtonClicked();
    void onRefreshDevicesClicked();
    void updateDeviceList();
    void onLogoutButtonClicked();

private:
    void setupConnections();
    void navigateTo(QWidget* newWindow);
    void createDeviceBox(const std::string& deviceName);
    void handleRefreshSpinner();

    Ui::Settings *ui;
    CameraFunctionality* m_cameraFunctionality;
    QTimer* m_refreshSpinnerTimer;
    int m_spinnerAngle;
};

#endif // SETTINGS_H