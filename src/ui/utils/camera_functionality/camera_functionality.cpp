#include "camera_functionality.h"
#include <QImage>
#include <QPixmap>
#include <iostream>
#include "src/key_exchange/utils.h"
#include <sodium.h>
#include "src/ui/windows/settings/settings.h"

CameraFunctionality::CameraFunctionality(QWidget* parent)
    : QObject(parent)
    , m_parent(parent)
    , m_scanDialog(nullptr)
    , m_cameraLabel(nullptr)
    , m_timer(nullptr)
    , m_isScanning(false)
{
}

CameraFunctionality::~CameraFunctionality()
{
    cleanupScanDialog();
}

QDialog* CameraFunctionality::createScanDialog()
{
    QDialog* dialog = new QDialog(m_parent);
    dialog->setWindowTitle("Scan QR Code");
    dialog->setMinimumSize(640, 480);

    QVBoxLayout* layout = new QVBoxLayout(dialog);
    
    // Create and setup camera preview label
    m_cameraLabel = new QLabel(dialog);
    m_cameraLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(m_cameraLabel);

    // Add close button
    QPushButton* closeButton = createCloseButton(dialog);
    layout->addWidget(closeButton);

    // Setup dialog connections
    setupDialogConnections(dialog, closeButton);

    return dialog;
}

QPushButton* CameraFunctionality::createCloseButton(QWidget* parent)
{
    QPushButton* button = new QPushButton("Close", parent);
    button->setStyleSheet(R"(
        QPushButton {
            font-size: 14px;
            font-weight: bold;
            color: #6c5ce7;
            background-color: white;
            border: 2px solid #6c5ce7;
            border-radius: 6px;
            padding: 8px 16px;
            margin: 10px;
        }
        QPushButton:hover {
            background-color: #f5f3ff;
        }
        QPushButton:pressed {
            background-color: #eeeaff;
        }
    )");
    return button;
}

void CameraFunctionality::setupDialogConnections(const QDialog* dialog, const QPushButton* closeButton)
{
    connect(closeButton, &QPushButton::clicked, dialog, &QDialog::close);
    connect(dialog, &QDialog::finished, this, [this]() {
        cleanupScanDialog();
    });
}

bool CameraFunctionality::initializeCamera()
{
    m_camera.open(0);
    if (!m_camera.isOpened()) {
        StyledMessageBox::error(m_parent, "Camera Error", 
            "Failed to access camera. Please make sure you have granted camera permissions.");
        return false;
    }
    return true;
}

void CameraFunctionality::setupCameraTimer()
{
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &CameraFunctionality::processFrame);
    m_isScanning = true;
    m_timer->start(30); // 30ms = ~33fps
}

void CameraFunctionality::showScanDialog()
{
    m_scanDialog = createScanDialog();
    if (initializeCamera()) {
        setupCameraTimer();
        m_scanDialog->exec();
    }
}

void CameraFunctionality::cleanupScanDialog()
{
    m_isScanning = false;
    if (m_timer) {
        m_timer->stop();
        delete m_timer;
        m_timer = nullptr;
    }
    if (m_camera.isOpened()) {
        m_camera.release();
    }
    if (m_scanDialog) {
        delete m_scanDialog;
        m_scanDialog = nullptr;
    }
    m_cameraLabel = nullptr;
}

void CameraFunctionality::processFrame()
{
    if (!m_isScanning || !m_camera.isOpened() || !m_cameraLabel) {
        return;
    }

    try {
        cv::Mat frame;
        m_camera >> frame;
        if (frame.empty()) return;

        // Convert frame to RGB for display
        cv::Mat displayFrame;
        cv::cvtColor(frame, displayFrame, cv::COLOR_BGR2RGB);

        // Try to detect QR code
        cv::QRCodeDetector qrDetector;
        std::vector<cv::Point> points;
        cv::Mat straight_qrcode;
        std::string decodedInfo = qrDetector.detectAndDecode(frame, points, straight_qrcode);

        if (!decodedInfo.empty() && points.size() == 4) {
            // Draw rectangle around QR code
            for (int i = 0; i < 4; i++) {
                cv::line(displayFrame, points[i], points[(i + 1) % 4], cv::Scalar(0, 255, 0), 2);
            }

            std::cout << "Decoded QR code: " << decodedInfo << std::endl;

            if (isValidQRCodeData(decodedInfo)) {
                // Lock camera settings to prevent auto-adjustment
                m_camera.set(cv::CAP_PROP_AUTOFOCUS, 0);
                m_camera.set(cv::CAP_PROP_AUTO_EXPOSURE, 0);

                // Display decoded text
                cv::putText(displayFrame, "Public Key Found", cv::Point(10, 30),
                            cv::FONT_HERSHEY_SIMPLEX, 1.0, cv::Scalar(0, 255, 0), 2);

                QString safeDecodedInfo = QString::fromStdString(decodedInfo);
                
                m_isScanning = false;
                if (m_timer) {
                    m_timer->stop();
                }
                m_camera.release();
                
                if (m_scanDialog) {
                    m_scanDialog->close();
                }
                
                if (!safeDecodedInfo.isEmpty()) {
                    Settings* settings = qobject_cast<Settings*>(m_parent);
                    if (settings) {
                        settings->handleDeviceConnection(safeDecodedInfo);
                    }
                } else {
                    StyledMessageBox::error(m_parent, "QR Code Error", 
                        "Failed to decode QR code data");
                }
                
                cleanupScanDialog();
                return;
            } else {
                // Log validation failure
                std::cerr << "QR code validation failed" << std::endl;
            }
        }

        // Display the frame
        QImage image(displayFrame.data, displayFrame.cols, displayFrame.rows, 
                    static_cast<int>(displayFrame.step), QImage::Format_RGB888);
        
        // Create a deep copy of the QImage to ensure it owns its data
        QImage imageCopy = image.copy();
        
        // Convert to QPixmap and scale
        QPixmap pixmap = QPixmap::fromImage(imageCopy);
        pixmap = pixmap.scaled(m_cameraLabel->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation);
        
        // Update the label
        m_cameraLabel->setPixmap(pixmap);

    } catch (const cv::Exception& e) {
        std::cerr << "OpenCV error in processFrame: " << e.what() << std::endl;
        resetCamera();
    } catch (const std::exception& e) {
        std::cerr << "Error in processFrame: " << e.what() << std::endl;
    }
}

void CameraFunctionality::resetCamera()
{
    m_camera.release();
    m_camera.open(0);
    if (!m_camera.isOpened()) {
        StyledMessageBox::error(m_parent, "Camera Error", 
            "Failed to reset camera. Please check your camera connection.");
        cleanupScanDialog();
    }
}

bool CameraFunctionality::isValidQRCodeData(const std::string& decodedInfo)
{
    if (decodedInfo.length() < 43 || decodedInfo.length() > 44) {
        std::cerr << "Invalid QR code data length. Expected 43-44 characters, got " 
                  << decodedInfo.length() << std::endl;
        return false;
    }

    for (char c : decodedInfo) {
        if (!isalnum(c) && c != '+' && c != '/' && c != '=') {
            std::cerr << "Invalid base64 data detected in QR code" << std::endl;
            return false;
        }
    }

    return true;
}