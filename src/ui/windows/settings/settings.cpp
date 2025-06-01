#include "settings.h"
#include "ui_settings.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "../../utils/navbar/navbar.h"
#include "src/key_exchange/utils.h"
#include <QVBoxLayout>
#include <QFileDialog>
#include <QLineEdit>
#include <QDialog>
#include <QTimer>
#include <QCheckBox>
#include <QImage>
#include <QImageReader>
#include <QPixmap>
#include <QLabel>
#include <opencv2/opencv.hpp>
#include <nlohmann/json.hpp>
#include <QDebug>

Settings::Settings(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Settings)
{
    ui->setupUi(this);
    setupConnections();

    // Connect WindowManager signal to handle navbar highlighting
    connect(&WindowManager::instance(), &WindowManager::windowShown,
            this, &Settings::onWindowShown);
}

Settings::~Settings()
{
    delete ui;
}

void Settings::setupConnections()
{
    // Connect passphrase fields to validation
    connect(ui->currentPassphrase, &QLineEdit::textChanged, this, &Settings::validatePassphrase);
    connect(ui->currentPassphrase, &QLineEdit::textChanged, this, &Settings::validatePassphrase);
    connect(ui->confirmPassphrase, &QLineEdit::textChanged, this, &Settings::validatePassphrase);

    // Connect passphrase section buttons
    connect(ui->passphraseCancelButton, &QPushButton::clicked, this, &Settings::onPassphraseCancelClicked);
    connect(ui->passphraseSaveButton, &QPushButton::clicked, this, &Settings::onPassphraseSaveClicked);

    // Connect auth section buttons
    connect(ui->authCancelButton, &QPushButton::clicked, this, &Settings::onAuthCancelClicked);
    connect(ui->authSaveButton, &QPushButton::clicked, this, &Settings::onAuthSaveClicked);

    // Connect NavBar signals
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        connect(navbar, &NavBar::receivedClicked, this, &Settings::onReceivedButtonClicked);
        connect(navbar, &NavBar::sentClicked, this, &Settings::onSentButtonClicked);
        connect(navbar, &NavBar::sendFileClicked, this, &Settings::onSendFileButtonClicked);
        connect(navbar, &NavBar::logoutClicked, this, &Settings::onLogoutButtonClicked);
        connect(navbar, &NavBar::settingsClicked, this, &Settings::onSettingsButtonClicked);
    }
    connect(ui->scanQRButton, &QPushButton::clicked, this, &Settings::onScanQRButtonClicked);
}

void Settings::validatePassphrase()
{
    QString newPassphrase = ui->newPassphrase->text();
    QString confirmPassphrase = ui->confirmPassphrase->text();

    if (newPassphrase.isEmpty() && confirmPassphrase.isEmpty()) {
        ui->passphraseRequirements->setText("Passphrase must be between 20 and 64 characters");
        ui->passphraseRequirements->setStyleSheet("font-size: 12px; color: #636e72; margin-top: 5px;");
        return;
    }

    if (newPassphrase == confirmPassphrase) {
        ui->passphraseRequirements->setText("Passphrases match");
        ui->passphraseRequirements->setStyleSheet("font-size: 12px; color: #27ae60; margin-top: 5px;");
    } else {
        ui->passphraseRequirements->setText("Passphrases do not match");
        ui->passphraseRequirements->setStyleSheet("font-size: 12px; color: #e74c3c; margin-top: 5px;");
    }
}

void Settings::navigateTo(QWidget* newWindow)
{
    newWindow->setParent(this->parentWidget());  // Set the same parent
    newWindow->show();
    this->setAttribute(Qt::WA_DeleteOnClose);  // Mark for deletion when closed
    close();  // This will trigger deletion due to WA_DeleteOnClose
}

void Settings::onReceivedButtonClicked()
{
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showReceived();
}

void Settings::onSentButtonClicked()
{
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showSent();
}

void Settings::onSendFileButtonClicked()
{   
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    WindowManager::instance().showSendFile();
}

void Settings::onSettingsButtonClicked()
{   
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
}

void Settings::onWindowShown(const QString& windowName) const
{
    // Find the navbar and update its active button
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        navbar->setActiveButton(windowName);
    }
}

void Settings::onPassphraseCancelClicked()
{
    // Clear all passphrase fields
    ui->currentPassphrase->clear();
    ui->newPassphrase->clear();
    ui->confirmPassphrase->clear();
    
    // Navigate back to the previous window
    WindowManager::instance().showReceived();
}

void Settings::onPassphraseSaveClicked()
{
    // TODO: Implement passphrase change functionality
    StyledMessageBox::info(this, "Not Implemented", "Passphrase change functionality is not yet implemented.");
}

void Settings::onAuthCancelClicked()
{
    // Clear auth code input
    ui->authCodeInput->clear();
    
    // Navigate back to the previous window
    WindowManager::instance().showReceived();
}

void Settings::onAuthSaveClicked()
{
    // TODO: Implement auth code verification functionality
    StyledMessageBox::info(this, "Not Implemented", "Auth code verification functionality is not yet implemented.");
}

void Settings::onLogoutButtonClicked() {
    // TODO: Implement logout functionality
    StyledMessageBox::info(this, "Not Implemented", "Logout functionality is not yet implemented.");
}

void Settings::onScanQRButtonClicked()
{
    m_scanDialog = createScanDialog();
    if (!m_scanDialog) return;

    if (!initializeCamera()) {
        cleanupScanDialog();
        return;
    }

    setupCameraTimer();
    showScanDialog();
}

QDialog* Settings::createScanDialog()
{
    QDialog* dialog = new QDialog(this);
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

QPushButton* Settings::createCloseButton(QWidget* parent)
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

void Settings::setupDialogConnections(const QDialog* dialog, const QPushButton* closeButton)
{
    connect(closeButton, &QPushButton::clicked, dialog, &QDialog::close);
    connect(dialog, &QDialog::finished, this, [this]() {
        cleanupScanDialog();
    });
}

bool Settings::initializeCamera()
{
    m_camera.open(0);
    if (!m_camera.isOpened()) {
        StyledMessageBox::error(this, "Camera Error", 
            "Failed to access camera. Please make sure you have granted camera permissions.");
        return false;
    }
    return true;
}

void Settings::setupCameraTimer()
{
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &Settings::processFrame);
    m_isScanning = true;
    m_timer->start(30); // 30ms = ~33fps
}

void Settings::showScanDialog() const
{
    m_scanDialog->exec();
}

void Settings::cleanupScanDialog()
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

void Settings::processFrame()
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
                    if (StyledMessageBox::confirmDialog(this, "Connection Request", 
                        "A new device wants to connect with you.\n\nDo you wish to accept this connection?")) {
                        StyledMessageBox::success(this, "Connection Accepted", 
                            "Connection request has been accepted.");
                        qDebug() << "Connection accepted with public key:" << safeDecodedInfo;
                    } else {
                        StyledMessageBox::info(this, "Connection Denied", 
                            "Connection request has been denied.");
                        // TODO: Implement connection denial logic
                    }
                } else {
                    StyledMessageBox::error(this, "QR Code Error", 
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

void Settings::resetCamera()
{
    m_camera.release();
    m_camera.open(0);
    if (!m_camera.isOpened()) {
        StyledMessageBox::error(this, "Camera Error", 
            "Failed to reset camera. Please check your camera connection.");
        cleanupScanDialog();
    }
}

bool Settings::isValidQRCodeData(const std::string& decodedInfo)
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