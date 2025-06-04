#include "send_file.h"
#include "ui_send_file.h"
#include <src/ui/utils/messagebox.h>
#include <src/ui/utils/window_manager/window_manager.h>
#include <src/ui/utils/navbar/navbar.h>
#include <QFileInfo>
#include <QFileDialog>
#include <QLineEdit>
#include <QCheckBox>
#include "src/communication/send_file_to/send_file_to.h"


SendFile::SendFile(QWidget *parent)
    : QWidget(parent)
      , ui(new Ui::SendFile) {
    ui->setupUi(this);
    setupConnections();
}

SendFile::~SendFile() {
    delete ui;
}

void SendFile::setupConnections() {
    connect(ui->browseButton, &QPushButton::clicked, this, &SendFile::onBrowseClicked);
    connect(ui->sendButton, &QPushButton::clicked, this, &SendFile::onSendClicked);

    // Connect NavBar signals
    if (NavBar *navbar = findChild<NavBar *>()) {
        connect(navbar, &NavBar::receivedClicked, this, &SendFile::onReceivedButtonClicked);
        connect(navbar, &NavBar::sentClicked, this, &SendFile::onSentButtonClicked);
        connect(navbar, &NavBar::settingsClicked, this, &SendFile::onSettingsButtonClicked);
        connect(navbar, &NavBar::sendFileClicked, this, &SendFile::onSendFileButtonClicked);
    }
}

void SendFile::onBrowseClicked() {
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
void SendFile::onSendClicked() {
    const QString filePath = ui->filePathInput->text();
    if (filePath.isEmpty()) {
        StyledMessageBox::warning(this, "No File Selected", "Please select a file to send.");
        return;
    }

    send_file_to(ui->usernameInput->text().toStdString(), ui->filePathInput->text().toStdString());

    StyledMessageBox::info(this, "File Sent", "File has been sent successfully!");
}

void SendFile::navigateTo(QWidget *newWindow) {
    newWindow->setParent(this->parentWidget()); // Set the same parent
    newWindow->show();
    this->setAttribute(Qt::WA_DeleteOnClose); // Mark for deletion when closed
    close(); // This will trigger deletion due to WA_DeleteOnClose
}

void SendFile::onReceivedButtonClicked() const {
    ui->usernameInput->clear();
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
    WindowManager::instance().showReceived();
}

void SendFile::onSentButtonClicked() const {
    ui->usernameInput->clear();
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
    WindowManager::instance().showSent();
}

void SendFile::onSendFileButtonClicked() const {
    ui->usernameInput->clear();
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
}

void SendFile::onSettingsButtonClicked() const {
    ui->filePathInput->clear();
    ui->fileDetailsLabel->clear();
    ui->usernameInput->clear();
    WindowManager::instance().showSettings();
}
