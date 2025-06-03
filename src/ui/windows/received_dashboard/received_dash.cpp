#include "received_dash.h"
#include "ui_received_dash.h"
#include "src/ui/utils/messagebox.h"
#include "src/ui/utils/window_manager/window_manager.h"
#include "src/ui/utils/navbar/navbar.h"
#include "src/ui/windows/sent_dashboard/sent_dash.h"
#include <QFileDialog>
#include <QTimer>
#include <QCheckBox>
#include "src/auth/logout.h"

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
    if (NavBar* navbar = findChild<NavBar*>()) {
        connect(navbar, &NavBar::sentClicked, this, &Received::onSentButtonClicked);
        connect(navbar, &NavBar::sendFileClicked, this, &Received::onSendFileButtonClicked);
        connect(navbar, &NavBar::settingsClicked, this, &Received::onSettingsButtonClicked);
        connect(navbar, &NavBar::logoutClicked, this, &Received::onLogoutButtonClicked);
    }
}

void Received::setupFileList() const {
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
}

void Received::onFileItemClicked(const FileItemWidget* widget)
{
    showFileMetadata(widget);
}

void Received::onSentButtonClicked()
{
    WindowManager::instance().showSent();
}

void Received::onSettingsButtonClicked()
{
    WindowManager::instance().showSettings(); 
}

void Received::showFileMetadata(const FileItemWidget* widget)
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

// navbar button
void Received::onSendFileButtonClicked()
{
    WindowManager::instance().showSendFile();
}

void Received::onWindowShown(const QString& windowName) const {
    // Find the navbar and update its active button
    if (NavBar* navbar = findChild<NavBar*>()) {
        navbar->setActiveButton(windowName);
    }
}

void Received::onLogoutButtonClicked()
{
    logout();
    WindowManager::instance().showLogin();
}

void Received::onDownloadFileClicked(FileItemWidget* widget)
{
    StyledMessageBox::info(this, "Not Implemented", "Download functionality is not yet implemented.");
}