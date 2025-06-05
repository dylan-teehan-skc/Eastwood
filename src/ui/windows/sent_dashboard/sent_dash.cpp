#include "sent_dash.h"
#include "ui_sent_dash.h"
#include "src/ui/utils/messagebox.h"
#include "src/ui/utils/window_manager/window_manager.h"
#include "src/ui/utils/byte_converter/byte_converter.h"
#include <QVBoxLayout>
#include <QDialog>
#include <QScrollArea>
#include <QTimer>
#include <QCheckBox>
#include <QPainter>
#include <QPen>
#include <QColor>
#include <QIcon>
#include <QPixmap>

#include "src/communication/ReceiveFlow.h"
#include "src/communication/revoke_file/revoke_file.h"
#include "src/sql/queries.h"
#include "src/ui/utils/input_validation/name_validator.h"

// Sent implementation
Sent::Sent(QWidget *parent, QWidget* receivedWindow)
    : QWidget(parent)
    , ui(new Ui::Sent)
    , m_receivedWindow(receivedWindow)
    , m_spinnerAngle(0)
{
    ui->setupUi(this);
    setupConnections();
    setupFileList();
    refreshFileList();

    m_refreshSpinnerTimer = new QTimer(this);
    connect(m_refreshSpinnerTimer, &QTimer::timeout, this, &Sent::handleRefreshSpinner);
}

Sent::~Sent()
{
    delete ui;
}

void Sent::setupConnections()
{
    // Connect the send button
    connect(ui->sendButton, &QPushButton::clicked, this, &Sent::onSendFileButtonClicked);
    connect(ui->refreshButton, &QPushButton::clicked, this, &Sent::onRefreshButtonClicked);
    connect(ui->showAuthCodeButton, &QPushButton::clicked, this, &Sent::onShowAuthCodeButtonClicked);
}

void Sent::setupFileList() const {
    ui->fileList->setSpacing(2);
    ui->fileList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->fileList->setSelectionMode(QAbstractItemView::NoSelection);
}

void Sent::addFileItem(const QString& fileName,
                         const QString& fileSize,
                         const QString& timestamp,
                         const QString& owner,
                         std::string uuid,
                         std::string mime_type)
{
    auto* item = new QListWidgetItem(ui->fileList);
    auto* widget = new FileItemWidget(fileName, fileSize, timestamp, owner, uuid, mime_type,
                                    FileItemWidget::Mode::Sent, this);

    connect(widget, &FileItemWidget::revokeAccessClicked, this, &Sent::onRevokeAccessClicked);
    connect(widget, &FileItemWidget::deleteFileClicked, this, &Sent::onDeleteFileClicked);
    connect(widget, &FileItemWidget::fileClicked, this, &Sent::onFileItemClicked);
    connect(widget, &FileItemWidget::downloadFileClicked, this, &Sent::onDownloadFileClicked);

    item->setSizeHint(widget->sizeHint());
    ui->fileList->addItem(item);
    ui->fileList->setItemWidget(item, widget);
}

void Sent::refreshFileList()
{
    ui->fileList->clear();

    auto metadata = get_file_metadata(true);

    ui->noFilesLabel->setVisible(metadata.empty());

    for (const auto& [file_name, file_size, mime_type, uuid, username] : metadata) {
        addFileItem(QString::fromStdString(file_name), 
                   QString::fromStdString(convertFileSizeToHumanReadable(file_size)), 
                   "", 
                   QString::fromStdString(username), 
                   uuid, 
                   mime_type);
    }
}

void Sent::onFileItemClicked(const FileItemWidget* widget)
{
    showFileMetadata(widget);
}

void Sent::onRevokeAccessClicked(const FileItemWidget* widget)
{
    // Create revoke access dialog
    QDialog* revokeDialog = new QDialog(this);
    revokeDialog->setWindowTitle("Revoke Access");
    revokeDialog->setFixedSize(400, 350);
    revokeDialog->setStyleSheet(R"(
        QDialog {
            background-color: #f5f6fa;
            font-family: ".SF NS", "SF Pro", "Helvetica Neue", Arial, sans-serif;
        }
        QLabel {
            color: #2d3436;
            font-size: 14px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        QCheckBox {
            color: #2d3436;
            font-size: 13px;
            padding: 12px;
            spacing: 12px;
            border-radius: 6px;
            background-color: white;
            border: 1px solid transparent;
            margin: 2px 0;
        }
        QCheckBox:hover {
            background-color: #f1f2f6;
            border: 1px solid #dfe6e9;
        }
        QCheckBox::indicator {
            width: 22px;
            height: 22px;
            border: 2px solid #dfe6e9;
            border-radius: 4px;
            background-color: white;
        }
        QCheckBox::indicator:hover {
            border-color: #6c5ce7;
        }
        QCheckBox::indicator:checked {
            background-color: #6c5ce7;
            border-color: #6c5ce7;
            image: url(:/icons/logos/check.svg);
        }
        QCheckBox::indicator:checked:hover {
            background-color: #5049c9;
            border-color: #5049c9;
        }
        QPushButton {
            font-size: 14px;
            padding: 8px 16px;
            border-radius: 6px;
            min-width: 100px;
            font-weight: bold;
        }
        QPushButton#acceptButton {
            background-color: #e74c3c;
            color: white;
            border: none;
        }
        QPushButton#acceptButton:hover {
            background-color: #c0392b;
        }
        QPushButton#acceptButton:pressed {
            background-color: #a93226;
        }
        QPushButton#cancelButton {
            background-color: white;
            color: #2d3436;
            border: 2px solid #dfe6e9;
        }
        QPushButton#cancelButton:hover {
            background-color: #f1f2f6;
            border-color: #2d3436;
        }
    )");

    auto* layout = new QVBoxLayout(revokeDialog);
    layout->setSpacing(10);
    layout->setContentsMargins(25, 25, 25, 25);

    // Add header label
    auto* headerLabel = new QLabel(QString("Uncheck users to remove their access to:\n%1").arg(widget->getFileName()), revokeDialog);
    headerLabel->setWordWrap(true);
    layout->addWidget(headerLabel);

    // Add scroll area for checkboxes
    auto* scrollArea = new QScrollArea(revokeDialog);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setStyleSheet(R"(
        QScrollArea {
            background-color: transparent;
            border: none;
        }
        QScrollBar:vertical {
            border: none;
            background: #f5f6fa;
            width: 8px;
            margin: 0;
        }
        QScrollBar::handle:vertical {
            background: #dfe6e9;
            border-radius: 4px;
            min-height: 20px;
        }
        QScrollBar::handle:vertical:hover {
            background: #b2bec3;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
            border: none;
            background: none;
        }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
            background: none;
        }
    )");

    auto* scrollWidget = new QWidget(scrollArea);
    auto* scrollLayout = new QVBoxLayout(scrollWidget);
    scrollLayout->setSpacing(2);
    scrollLayout->setContentsMargins(0, 0, 0, 0);

    QStringList users = {};
    std::vector<std::string> usernames = get_file_recipients(widget->getUuid());

    auto* ptr = usernames.data();
    while (ptr < usernames.data() + usernames.size()) {
        users.emplace_back(QString::fromStdString(*ptr));
        ++ptr;
    }

    QList<QCheckBox*> checkboxes;
    for (const QString& user : users) {
        auto* checkbox = new QCheckBox(user, scrollWidget);
        checkbox->setChecked(true);  // Pre-check all boxes
        scrollLayout->addWidget(checkbox);
        checkboxes.append(checkbox);
    }

    scrollLayout->addStretch();
    scrollArea->setWidget(scrollWidget);
    layout->addWidget(scrollArea);

    // Add buttons
    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(10);

    auto* acceptButton = new QPushButton("Remove Access", revokeDialog);
    acceptButton->setObjectName("acceptButton");
    
    auto* cancelButton = new QPushButton("Cancel", revokeDialog);
    cancelButton->setObjectName("cancelButton");

    buttonLayout->addStretch();
    buttonLayout->addWidget(cancelButton);
    buttonLayout->addWidget(acceptButton);

    layout->addLayout(buttonLayout);

    // Connect buttons
    connect(acceptButton, &QPushButton::clicked, [=]() {
        std::vector<std::string> selectedUsers;
        for (auto* checkbox : checkboxes) {
            if (!checkbox->isChecked()) {
                selectedUsers.emplace_back(checkbox->text().toStdString());
            }
        }

        if (selectedUsers.empty()) {
            StyledMessageBox::warning(this, "No Changes Made", 
                                    "Please uncheck at least one user to remove their access.");
            return;
        }

        QString message = QString("Access will be removed for the unchecked users");
        StyledMessageBox::info(this, "Access Removed", message);
        revokeDialog->accept();

        // call to fred
        try {
            refresh_access(selectedUsers, widget->getUuid());

        } catch (...) {
            StyledMessageBox::warning(this, "Failed. Try again: ", message);
        }
    });

    connect(cancelButton, &QPushButton::clicked, revokeDialog, &QDialog::reject);

    revokeDialog->exec();
    delete revokeDialog;
}

void Sent::onDeleteFileClicked(const FileItemWidget* widget)
{
    if (StyledMessageBox::question(this, "Delete File",
                                 QString("Are you sure you want to delete file: %1?")
                                 .arg(widget->getFileName()))) {
        delete_file(widget->getUuid());
        StyledMessageBox::info(this, "File Deleted",
                             QString("File deleted: %1").arg(widget->getFileName()));
        refreshFileList();
    }
}

void Sent::showFileMetadata(const FileItemWidget* widget)
{
    StyledMessageBox::info(this, "File Details",
                       QString("File Details:\n\nName: %1\nSize: %2\nShared to: %3\nTimestamp: %4")
                       .arg(widget->getFileName())
                       .arg(widget->getFileSize())
                       .arg(widget->getOwner())
                       .arg(widget->getTimestamp()));
}

void Sent::sendFileToUser(const QString& username, const QString& fileId)
{
    // TODO: Implement file sharing logic
}


void Sent::onDownloadFileClicked(FileItemWidget* widget)
{
    download_file(widget->getUuid(), widget->getMimeType(), widget->getFileName().toStdString());
}

void Sent::onSendFileButtonClicked()
{
    WindowManager::instance().showSendFile();
}

void Sent::onRefreshButtonClicked()
{
    m_spinnerAngle = 0;
    m_refreshSpinnerTimer->start(50);

    refreshFileList();

    //1 second
    QTimer::singleShot(1000, [this]() {
        m_refreshSpinnerTimer->stop();
        ui->refreshButton->setIcon(QIcon());
    });
}

void Sent::handleRefreshSpinner()
{
    m_spinnerAngle = (m_spinnerAngle + 30) % 360;
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.translate(8, 8);
    painter.rotate(m_spinnerAngle);
    painter.setPen(QPen(QColor("#6c5ce7"), 2));
    painter.drawLine(0, -6, 0, 6);
    painter.drawLine(-6, 0, 6, 0);
    ui->refreshButton->setIcon(QIcon(pixmap));
    ui->refreshButton->setIconSize(QSize(16, 16));
}

void Sent::onShowAuthCodeButtonClicked()
{
    QString errorMessage;
    QString username = StyledMessageBox::getUsername(this, errorMessage);
    
    if (!username.isEmpty()) {
        if (NameValidator::validateUsername(username, errorMessage)) {
            QString authCode = "123456";
            StyledMessageBox::displayCode(this, "Authentication Code", 
                QString("Authentication code for user %1:").arg(username), authCode);
        } else {
            StyledMessageBox::warning(this, "Error", errorMessage);
        }
    } else if (!errorMessage.isEmpty()) {
        StyledMessageBox::warning(this, "Error", errorMessage);
    }
}