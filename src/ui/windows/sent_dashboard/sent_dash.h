#ifndef SENT_DASH_H
#define SENT_DASH_H

#include <QWidget>
#include <QListWidget>
#include <QListWidgetItem>
#include <QTimer>
#include "src/ui/utils/file_item_widget/file_item_widget.h"
#include "src/ui/utils/navbar/navbar.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Sent; }
QT_END_NAMESPACE

class Sent : public QWidget {
    Q_OBJECT

public:
    explicit Sent(QWidget *parent = nullptr, QWidget* receivedWindow = nullptr);
    ~Sent() override;

private slots:
    void onFileItemClicked(const FileItemWidget* widget);
    void onRevokeAccessClicked(const FileItemWidget* widget);
    void onDeleteFileClicked(const FileItemWidget* widget);
    void onDownloadFileClicked(FileItemWidget* widget);
    void onSendFileButtonClicked();
    void onRefreshButtonClicked();
    void handleRefreshSpinner();

private:
    Ui::Sent *ui;
    QWidget* m_receivedWindow;
    QTimer* m_refreshSpinnerTimer;
    int m_spinnerAngle;
    void setupConnections();
    void setupFileList() const;
    void refreshFileList();
    void addFileItem(const QString& fileName,
                         const QString& fileSize,
                         const QString& timestamp,
                         const QString& owner,
                         std::string uuid,
                         std::string mime_type);
    void showFileMetadata(const FileItemWidget* widget);
    void sendFileToUser(const QString& username, const QString& fileId);
};

#endif // SENT_DASH_H