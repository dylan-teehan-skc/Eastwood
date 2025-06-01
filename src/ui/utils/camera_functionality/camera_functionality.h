#ifndef CAMERA_FUNCTIONALITY_H
#define CAMERA_FUNCTIONALITY_H

#include <QDialog>
#include <QLabel>
#include <QTimer>
#include <QPushButton>
#include <QVBoxLayout>
#include <opencv2/opencv.hpp>
#include <opencv2/objdetect.hpp>
#include "src/ui/utils/messagebox.h"
#include "src/auth/register_device/register_device.h"
#include "src/utils/ConversionUtils.h"

class CameraFunctionality : public QObject {
    Q_OBJECT

public:
    explicit CameraFunctionality(QWidget* parent = nullptr);
    ~CameraFunctionality();

    QDialog* createScanDialog();
    void showScanDialog();
    void cleanupScanDialog();

private slots:
    void processFrame();

private:
    QWidget* m_parent;
    QDialog* m_scanDialog;
    QLabel* m_cameraLabel;
    QTimer* m_timer;
    cv::VideoCapture m_camera;
    bool m_isScanning;

    QPushButton* createCloseButton(QWidget* parent);
    void setupDialogConnections(const QDialog* dialog, const QPushButton* closeButton);
    bool initializeCamera();
    void setupCameraTimer();
    void resetCamera();
    bool isValidQRCodeData(const std::string& decodedInfo);
};

#endif // CAMERA_FUNCTIONALITY_H
