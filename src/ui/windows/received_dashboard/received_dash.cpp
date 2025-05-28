#include "received_dash.h"
#include "ui_received_dash.h"
#include "../../utils/messagebox.h"
#include "../../utils/window_manager/window_manager.h"
#include "../../utils/navbar/navbar.h"
#include "../sent_dashboard/sent_dash.h"
#include <QFileDialog>
#include <QTimer>
#include <QCheckBox>

Received::Received(QWidget *parent, QWidget* sendFileWindow)
    : QWidget(parent)
    , ui(new Ui::Received)
    , m_sendFileWindow(sendFileWindow)
{
    ui->setupUi(this);
    setupConnections();
    setupFileList();
    refreshFileList();

    // Connect WindowManager signal to handle navbar highlighting
    connect(&WindowManager::instance(), &WindowManager::windowShown,
            this, &Received::onWindowShown);
}

Received::~Received()
{
    delete ui;
}

void Received::setupConnections()
{
    connect(ui->sendButton, &QPushButton::clicked, this, &Received::onSendButtonClicked);
    
    // Connect NavBar signals
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        connect(navbar, &NavBar::sentClicked, this, &Received::onSentButtonClicked);
        connect(navbar, &NavBar::sendFileClicked, this, &Received::onSendFileButtonClicked);
        connect(navbar, &NavBar::settingsClicked, this, &Received::onSettingsButtonClicked);
        connect(navbar, &NavBar::logoutClicked, this, &Received::onLogoutButtonClicked);
    }
}

void Received::setupFileList()
{
    ui->fileList->setSpacing(2);
    ui->fileList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->fileList->setSelectionMode(QAbstractItemView::NoSelection);
}

void Received::addFileItem(const QString& fileName,
                         const QString& fileSize,
                         const QString& timestamp,
                         const QString& owner)
{
    auto* item = new QListWidgetItem(ui->fileList);
    auto* widget = new FileItemWidget(fileName, fileSize, timestamp, owner, 
                                    FileItemWidget::Mode::Received, this);

    connect(widget, &FileItemWidget::deleteFileClicked, this, &Received::onDeleteFileClicked);
    connect(widget, &FileItemWidget::fileClicked, this, &Received::onFileItemClicked);
    connect(widget, &FileItemWidget::downloadFileClicked, this, &Received::onDownloadFileClicked);

    item->setSizeHint(widget->sizeHint());
    ui->fileList->addItem(item);
    ui->fileList->setItemWidget(item, widget);
}

void Received::refreshFileList()
{
    ui->fileList->clear();

    // TODO: Fetch actual files from server
    // Example data for demonstration
    addFileItem("Important Document.pdf", "2.5 MB", "2024-03-15 14:30", "John Doe");
    addFileItem("Project Presentation.pptx", "5.8 MB", "2024-03-14 09:15", "Alice Smith");
    addFileItem("Budget Report.xlsx", "1.2 MB", "2024-03-13 16:45", "Bob Johnson");
}

void Received::navigateTo(QWidget* newWindow)
{
    newWindow->setParent(this->parentWidget());  // Set the same parent
    newWindow->show();
    this->setAttribute(Qt::WA_DeleteOnClose);  // Mark for deletion when closed
    close();  // This will trigger deletion due to WA_DeleteOnClose
}

void Received::onSendButtonClicked()
{
    WindowManager::instance().showSendFile();
    hide();
}

void Received::onFileItemClicked(FileItemWidget* widget)
{
    showFileMetadata(widget);
}

void Received::onDeleteFileClicked(FileItemWidget* widget)
{
    if (StyledMessageBox::question(this, "Delete File",
                                 QString("Are you sure you want to delete file: %1?")
                                 .arg(widget->getFileName()))) {
        // TODO: Implement file deletion
        StyledMessageBox::info(this, "File Deleted",
                             QString("File deleted: %1").arg(widget->getFileName()));
    }
}

void Received::onSentButtonClicked()
{
    WindowManager::instance().showSent();
    hide();
}

void Received::onSettingsButtonClicked()
{
    WindowManager::instance().showSettings();
    hide();
}

void Received::showFileMetadata(FileItemWidget* widget)
{
    StyledMessageBox::info(this, "File Details",
                       QString("File Details:\n\nName: %1\nSize: %2\nShared by: %3\nTimestamp: %4")
                       .arg(widget->getFileName())
                       .arg(widget->getFileSize())
                       .arg(widget->getOwner())
                       .arg(widget->getTimestamp()));
}

void Received::sendFileToUser(const QString& username, const QString& fileId)
{
    // TODO: Implement file sharing logic
}

void Received::onSendFileButtonClicked()
{
    WindowManager::instance().showSendFile();
    hide();
}

void Received::onWindowShown(const QString& windowName)
{
    // Find the navbar and update its active button
    NavBar* navbar = findChild<NavBar*>();
    if (navbar) {
        navbar->setActiveButton(windowName);
    }
}

void Received::onLogoutButtonClicked()
{
    StyledMessageBox::info(this, "Not Implemented", "Logout functionality is not yet implemented.");
}

void Received::onDownloadFileClicked(FileItemWidget* widget)
{
    StyledMessageBox::info(this, "Not Implemented", "Download functionality is not yet implemented.");
}