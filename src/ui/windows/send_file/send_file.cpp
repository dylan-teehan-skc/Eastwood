#include "send_file.h"
#include "ui_send_file.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "../../utils/messagebox.h"
#include "../../utils/navbar/navbar.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileInfo>
#include <QFileDialog>
#include <QLineEdit>
#include <QDialog>
#include <QScrollArea>
#include <QTimer>
#include <QCheckBox>

SendFile::SendFile(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::SendFile)
{
    ui->setupUi(this);
    setupConnections();

    // Connect WindowManager signal to handle navbar highlighting
    connect(&WindowManager::instance(), &WindowManager::windowShown,
            this, &SendFile::onWindowShown);
}

SendFile::~SendFile()
{
    delete ui;
}

void SendFile::setupConnections()
{
    connect(ui->browseButton, &QPushButton::clicked, this, &SendFile::onBrowseClicked);
    connect(ui->sendButton, &QPushButton::clicked, this, &SendFile::onSendClicked);

    // Connect NavBar signals
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        connect(navbar, &NavBar::receivedClicked, this, &SendFile::onReceivedButtonClicked);
        connect(navbar, &NavBar::sentClicked, this, &SendFile::onSentButtonClicked);
        connect(navbar, &NavBar::settingsClicked, this, &SendFile::onSettingsButtonClicked);
        connect(navbar, &NavBar::logoutClicked, this, &SendFile::onLogoutButtonClicked);
        connect(navbar, &NavBar::sendFileClicked, this, &SendFile::onSendFileButtonClicked);
    }
}

void SendFile::onBrowseClicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Select File", "", "All Files (*.*)");
    if (!filePath.isEmpty()) {
        ui->filePathInput->setText(filePath);
        
        // Get file information
        QFileInfo fileInfo(filePath);
        QString fileName = fileInfo.fileName();
        qint64 size = fileInfo.size();
        QString sizeStr;
        
        // Convert size to human-readable format
        if (size < 1024) {
            sizeStr = QString("%1 B").arg(size);
        } else if (size < 1024 * 1024) {
            sizeStr = QString("%1 KB").arg(size / 1024.0, 0, 'f', 1);
        } else if (size < 1024 * 1024 * 1024) {
            sizeStr = QString("%1 MB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
        } else {
            sizeStr = QString("%1 GB").arg(size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
        }
        
        // Format the details text
        QString details = QString("File Details:\n\n"
                                "Name: %1\n"
                                "Size: %2\n"
                                "Type: %3\n"
                                "Last Modified: %4")
                                .arg(fileName)
                                .arg(sizeStr)
                                .arg(fileInfo.suffix().toUpper())
                                .arg(fileInfo.lastModified().toString("yyyy-MM-dd hh:mm:ss"));
        
        ui->fileDetailsLabel->setText(details);
    }
}

// purple send button in send_file.ui
void SendFile::onSendClicked()
{
    QString filePath = ui->filePathInput->text();
    if (filePath.isEmpty()) {
        StyledMessageBox::warning(this, "No File Selected", "Please select a file to send.");
        return;
    }

    // TODO: Implement file sending logic
    StyledMessageBox::info(this, "File Sent", "File has been sent successfully!");
}

void SendFile::navigateTo(QWidget* newWindow)
{
    newWindow->setParent(this->parentWidget());  // Set the same parent
    newWindow->show();
    this->setAttribute(Qt::WA_DeleteOnClose);  // Mark for deletion when closed
    close();  // This will trigger deletion due to WA_DeleteOnClose
}

void SendFile::onReceivedButtonClicked()
{   
    ui->usernameInput->clear();
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
    WindowManager::instance().showReceived();
    hide();
}

void SendFile::onSentButtonClicked()
{   
    ui->usernameInput->clear();
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
    WindowManager::instance().showSent();
    hide();
}

// navbar button
void SendFile::onSendFileButtonClicked()
{   
    ui->usernameInput->clear();
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
}

void SendFile::onSettingsButtonClicked()
{   
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
    ui->usernameInput->clear();
    WindowManager::instance().showSettings();
    hide();
}

void SendFile::onWindowShown(const QString& windowName)
{
    // Find the navbar and update its active button
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        navbar->setActiveButton(windowName);
    }
}

void SendFile::onLogoutButtonClicked()
{
    StyledMessageBox::info(this, "Not Implemented", "Logout functionality is not yet implemented.");
}