#include "file_item_widget.h"
#include <QVBoxLayout>
#include <QFileInfo>
#include <QStyle>
#include <QIcon>

FileItemWidget::FileItemWidget(const QString& fileName,
                          const QString& fileSize,
                          const QString& timestamp,
                          const QString& owner,
                          const std::string& uuid,
                          const std::string& mime_type,
                          Mode mode,
                          QWidget* parent)
    : QWidget(parent)
    , fileName(fileName)
    , fileSize(fileSize)
    , timestamp(timestamp)
    , owner(owner)
    , mode(mode)
    , uuid(uuid)
    , mime_type(mime_type)
{
    setupUI();
    setupConnections();
}

void FileItemWidget::setupUI()
{
    auto* mainLayout = new QHBoxLayout(this);
    mainLayout->setSpacing(16);
    mainLayout->setContentsMargins(20, 16, 20, 16);

    mainLayout->addWidget(createFileIconContainer());
    mainLayout->addLayout(createInfoLayout(), 1);
    mainLayout->addLayout(createButtonLayout());

    setCursor(Qt::PointingHandCursor);
}

QWidget* FileItemWidget::createFileIconContainer()
{
    auto* fileIconContainer = new QWidget(this);
    fileIconContainer->setFixedSize(42, 42);
    fileIconContainer->setStyleSheet(R"(
        background-color: #f5f6fa;
        border-radius: 8px;
    )");
    
    auto* fileTypeLabel = new QLabel(getFileTypeAbbreviation(fileName), fileIconContainer);
    fileTypeLabel->setAlignment(Qt::AlignCenter);
    fileTypeLabel->setStyleSheet(R"(
        font-size: 12px;
        font-weight: bold;
        color: #6c5ce7;
    )");
    fileTypeLabel->setFixedSize(42, 42);
    
    return fileIconContainer;
}

QLayout* FileItemWidget::createInfoLayout()
{
    auto* infoLayout = new QVBoxLayout();
    infoLayout->setSpacing(4);

    fileNameLabel = new QLabel(fileName, this);
    fileNameLabel->setStyleSheet("font-size: 15px; font-weight: 500; color: #2d3436;");

    detailsLabel = new QLabel(QString("%1 • %2 • Shared by %3")
                            .arg(fileSize)
                            .arg(timestamp)
                            .arg(owner), this);
    detailsLabel->setStyleSheet("font-size: 13px; color: #636e72;");

    infoLayout->addWidget(fileNameLabel);
    infoLayout->addWidget(detailsLabel);

    return infoLayout;
}

QLayout* FileItemWidget::createButtonLayout()
{
    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->setSpacing(8);
    buttonLayout->addStretch();

    buttonLayout->addWidget(createDownloadButton());

    if (mode == Mode::Sent) {
        buttonLayout->addWidget(createRevokeButton());
        buttonLayout->addWidget(createDeleteButton());
    }

    buttonLayout->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    return buttonLayout;
}

QPushButton* FileItemWidget::createDownloadButton()
{
    downloadButton = new QPushButton(this);
    downloadButton->setFixedSize(30, 30);
    downloadButton->setCursor(Qt::PointingHandCursor);
    downloadButton->setIcon(QIcon(":icons/logos/download.svg"));
    downloadButton->setIconSize(QSize(16, 16));
    downloadButton->setStyleSheet(R"(
        QPushButton {
            background-color: #6c5ce7;
            border: none;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #5049c9;
        }
        QPushButton:pressed {
            background-color: #4040b0;
        }
    )");
    return downloadButton;
}

QPushButton* FileItemWidget::createRevokeButton()
{
    revokeButton = new QPushButton("Revoke", this);
    revokeButton->setFixedSize(75, 30);
    revokeButton->setCursor(Qt::PointingHandCursor);
    revokeButton->setStyleSheet(R"(
        QPushButton {
            background-color: #6c5ce7;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #5049c9;
        }
        QPushButton:pressed {
            background-color: #4040b0;
        }
    )");
    return revokeButton;
}

QPushButton* FileItemWidget::createDeleteButton()
{
    deleteButton = new QPushButton("Delete", this);
    deleteButton->setFixedSize(75, 30);
    deleteButton->setCursor(Qt::PointingHandCursor);
    deleteButton->setStyleSheet(R"(
        QPushButton {
            background-color: #e74c3c;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #c0392b;
        }
        QPushButton:pressed {
            background-color: #a93226;
        }
    )");
    return deleteButton;
}

void FileItemWidget::setupConnections()
{
    connect(downloadButton, &QPushButton::clicked, [this]() {
        emit downloadFileClicked(this);
    });

    if (mode == Mode::Sent) {
        connect(revokeButton, &QPushButton::clicked, [this]() {
            emit revokeAccessClicked(this);
        });
        connect(deleteButton, &QPushButton::clicked, [this]() {
            emit deleteFileClicked(this);
        });
    }
}

QString FileItemWidget::getFileTypeAbbreviation(const QString& fileName)
{
    QFileInfo fileInfo(fileName);
    QString ext = fileInfo.suffix().toLower();
    
    if (ext == "pdf") return "PDF";
    if (ext == "doc" || ext == "docx") return "DOC";
    if (ext == "xls" || ext == "xlsx") return "XLS";
    if (ext == "ppt" || ext == "pptx") return "PPT";
    if (ext == "txt") return "TXT";
    if (ext == "zip" || ext == "rar") return "ZIP";
    if (ext == "jpg" || ext == "jpeg" || ext == "png") return "IMG";
    
    return ext.toUpper().left(3);
}