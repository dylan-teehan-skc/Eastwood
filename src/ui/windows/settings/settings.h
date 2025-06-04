#ifndef SETTINGS_H
#define SETTINGS_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include "src/ui/utils/camera_functionality/camera_functionality.h"
#include <QTimer>
#include "src/keys/session_token_manager.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Settings; }
QT_END_NAMESPACE

class Settings : public QWidget {
    Q_OBJECT

public:
    explicit Settings(QWidget *parent = nullptr);
    ~Settings() override;
    bool handleDeviceConnection(const QString& publicKey);

private slots:
    void onReceivedButtonClicked() const;
    void onSentButtonClicked() const;
    void onSendFileButtonClicked() const;
    void validatePassphrase() const;
    void onPassphraseCancelClicked() const;
    void onPassphraseSaveClicked();
    void onAuthCancelClicked() const;
    void onAuthVerifyClicked();
    void onSettingsButtonClicked() const;
    void onScanQRButtonClicked() const;
    void onRefreshDevicesClicked();
    void updateDeviceList();
    void onLogoutButtonClicked();

private:
    void setupConnections();
    void navigateTo(QWidget* newWindow);
    void createDeviceBox(const std::string& deviceName) const;
    void handleRefreshSpinner();
    void updateUsername();

    Ui::Settings *ui;
    CameraFunctionality* m_cameraFunctionality;
    QTimer* m_refreshSpinnerTimer;
    int m_spinnerAngle;
};

#endif // SETTINGS_H