#ifndef FILE_ITEM_WIDGET_H
#define FILE_ITEM_WIDGET_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>

class FileItemWidget : public QWidget {
    Q_OBJECT

public:
    enum class Mode {
        Received,
        Sent
    };

    explicit FileItemWidget(const QString& fileName, 
                          const QString& fileSize, 
                          const QString& timestamp,
                          const QString& owner,
                          Mode mode = Mode::Received,
                          QWidget* parent = nullptr);

    // Add getter methods
    QString getFileName() const { return fileName; }
    QString getFileSize() const { return fileSize; }
    QString getTimestamp() const { return timestamp; }
    QString getOwner() const { return owner; }

signals:
    void revokeAccessClicked(FileItemWidget* widget);
    void deleteFileClicked(FileItemWidget* widget);
    void fileClicked(FileItemWidget* widget);
    void downloadFileClicked(FileItemWidget* widget);

private:
    QLabel* fileNameLabel;
    QLabel* detailsLabel;
    QPushButton* revokeButton;
    QPushButton* deleteButton;
    QPushButton* downloadButton;
    QString fileName;
    QString fileSize;
    QString timestamp;
    QString owner;
    Mode mode;

    QWidget* createFileIconContainer();
    QLayout* createInfoLayout();
    QLayout* createButtonLayout();
    QPushButton* createDownloadButton();
    QPushButton* createRevokeButton();
    QPushButton* createDeleteButton();

    void setupUI();
    void setupConnections();

    static QString getFileTypeAbbreviation(const QString& fileName);
};

#endif // FILE_ITEM_WIDGET_H