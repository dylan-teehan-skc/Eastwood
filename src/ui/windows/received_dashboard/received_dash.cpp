#include "received_dash.h"
#include "ui_received_dash.h"
#include "src/ui/utils/messagebox.h"
#include "src/ui/utils/window_manager/window_manager.h"
#include "src/ui/utils/navbar/navbar.h"
#include "src/ui/windows/sent_dashboard/sent_dash.h"
#include "src/ui/utils/byte_converter/byte_converter.h"
#include <QTimer>
#include <QCheckBox>
#include <QTransform>
#include <QIcon>
#include <QPixmap>
#include <QPainter>
#include <QPen>
#include <QColor>
#include <iostream>

#include "src/communication/ReceiveFlow.h"
#include "src/ui/utils/input_validation/name_validator.h"

Received::Received(QWidget *parent, QWidget* sendFileWindow)
    : QWidget(parent)
    , ui(new Ui::Received)
    , m_sendFileWindow(sendFileWindow)
    , m_spinnerAngle(0)
{
    ui->setupUi(this);
    setupConnections();
    setupFileList();
    refreshFileList();

    m_refreshSpinnerTimer = new QTimer(this);
    connect(m_refreshSpinnerTimer, &QTimer::timeout, this, &Received::handleRefreshSpinner);
}

Received::~Received()
{
    delete ui;
}

void Received::setupConnections()
{
    connect(ui->navBar, &NavBar::receivedClicked, this, &Received::onReceivedButtonClicked);
    connect(ui->sendButton, &QPushButton::clicked, this, &Received::onSendButtonClicked);
    connect(ui->refreshButton, &QPushButton::clicked, this, &Received::onRefreshButtonClicked);
    connect(ui->showAuthCodeButton, &QPushButton::clicked, this, &Received::onShowAuthCodeButtonClicked);
}

void Received::setupFileList() const {
    ui->fileList->setSpacing(2);
    ui->fileList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->fileList->setSelectionMode(QAbstractItemView::NoSelection);
}

void Received::addFileItem(const QString& fileName,
                         const QString& fileSize,
                         const QString& timestamp,
                         const QString& owner,
                         std::string uuid,
                         std::string mime_type)
{
    auto* item = new QListWidgetItem(ui->fileList);
    auto* widget = new FileItemWidget(fileName, fileSize, timestamp, owner, uuid, mime_type,
                                    FileItemWidget::Mode::Received, this);

    connect(widget, &FileItemWidget::fileClicked, this, &Received::onFileItemClicked);
    connect(widget, &FileItemWidget::downloadFileClicked, this, &Received::onDownloadFileClicked);

    item->setSizeHint(widget->sizeHint());
    ui->fileList->addItem(item);
    ui->fileList->setItemWidget(item, widget);
}

void Received::refreshFileList()
{
    ui->fileList->clear();

    update_handshakes();
    update_messages();

    auto metadata = get_file_metadata();

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

void Received::onSendButtonClicked()
{
    WindowManager::instance().showSendFile();
}

void Received::onFileItemClicked(const FileItemWidget* widget)
{
    showFileMetadata(widget);
}

void Received::showFileMetadata(const FileItemWidget* widget)
{
    StyledMessageBox::info(this, "File Details",
                       QString("File Details:\n\nName: %1\nSize: %2\nShared by: %3")
                       .arg(widget->getFileName())
                       .arg(widget->getFileSize())
                       .arg(widget->getOwner()));
}

void Received::onDownloadFileClicked(FileItemWidget* widget)
{
    download_file(widget->getUuid(), widget->getMimeType(), widget->getFileName().toStdString());
}

void Received::onReceivedButtonClicked()
{
    std::cout << "Received button clicked" << std::endl;
    refreshFileList();
}

void Received::onRefreshButtonClicked()
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

void Received::handleRefreshSpinner()
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

void Received::onShowAuthCodeButtonClicked()
{
    QString errorMessage;
    QString username = StyledMessageBox::getUsername(this, errorMessage);

    if (!username.isEmpty()) {
        if (NameValidator::validateUsername(username, errorMessage)) {
            update_handshakes();

              auto their_device_ids = RatchetSessionManager::instance().get_device_ids_of_existing_handshakes(username.toStdString());
              auto bundles = get_keybundles(username.toStdString(), their_device_ids);
              RatchetSessionManager::instance().create_ratchets_if_needed(username.toStdString(), bundles);
              auto my_device_pub = get_public_key("device");
              their_device_ids = RatchetSessionManager::instance().get_device_ids_of_existing_handshakes(username.toStdString()); // update with  new

              auto code = concat_ordered(reinterpret_cast<const unsigned char *>(my_device_pub.data()),my_device_pub.size(), their_device_ids[0].data(), their_device_ids[0].size());
              auto base_code = bin2base64(code.data(), code.size());

              QString authCode = QString::fromStdString(base_code);
              StyledMessageBox::displayCode(this, "Authentication Code",
              QString("Authentication code for user %1:").arg(username), authCode);
          } else {
              StyledMessageBox::warning(this, "Error", errorMessage);
          }
    } else if (!errorMessage.isEmpty()) {
        StyledMessageBox::warning(this, "Error", errorMessage);
    }
}