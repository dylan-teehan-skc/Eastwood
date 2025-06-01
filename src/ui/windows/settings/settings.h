#ifndef SETTINGS_H
#define SETTINGS_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QDialog>
#include <QLabel>
#include <QTimer>
#include <opencv2/opencv.hpp>

QT_BEGIN_NAMESPACE
namespace Ui { class Settings; }
QT_END_NAMESPACE

struct QRCodeResult {
    std::string decodedInfo;
    std::vector<cv::Point> points;
    cv::Mat straight_qrcode;
    bool success = false;
};

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
    void onLogoutButtonClicked();
    void validatePassphrase();
    void onPassphraseCancelClicked();
    void onPassphraseSaveClicked();
    void onAuthCancelClicked();
    void onAuthSaveClicked();
    void onSettingsButtonClicked();
    void onScanQRButtonClicked();
    void processFrame();

private:
    void setupConnections();
    void navigateTo(QWidget* newWindow);

    // QR Code scanning functions
    QDialog* createScanDialog();
    QPushButton* createCloseButton(QWidget* parent);
    void setupDialogConnections(const QDialog* dialog, const QPushButton* closeButton);
    bool initializeCamera();
    void setupCameraTimer();
    void showScanDialog() const;
    void cleanupScanDialog();
    void resetCamera();
    bool isValidQRCodeData(const std::string& decodedInfo);

    Ui::Settings *ui;
    QDialog* m_scanDialog = nullptr;
    QLabel* m_cameraLabel = nullptr;
    cv::VideoCapture m_camera;
    QTimer* m_timer = nullptr;
    bool m_isScanning = false;
};

#endif // SETTINGS_H