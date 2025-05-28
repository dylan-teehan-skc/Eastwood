#ifndef SENT_DASH_H
#define SENT_DASH_H

#include <QWidget>
#include <QListWidget>
#include <QListWidgetItem>
#include "../../utils/file_item_widget/file_item_widget.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Sent; }
QT_END_NAMESPACE

class Sent : public QWidget {
    Q_OBJECT

public:
    explicit Sent(QWidget *parent = nullptr, QWidget* receivedWindow = nullptr);
    ~Sent() override;

private slots:
    void onFileItemClicked(FileItemWidget* widget);
    void onRevokeAccessClicked(FileItemWidget* widget);
    void onDeleteFileClicked(FileItemWidget* widget);
    void onDownloadFileClicked(FileItemWidget* widget);
    void onWindowShown(const QString& windowName);
    void onReceivedButtonClicked();
    void onSendFileButtonClicked();
    void onSettingsButtonClicked();
    void onLogoutButtonClicked();

private:
    Ui::Sent *ui;
    QWidget* m_receivedWindow;
    void setupConnections();
    void setupFileList();
    void refreshFileList();
    void addFileItem(const QString& fileName, const QString& fileSize, 
                    const QString& timestamp, const QString& owner);
    void showFileMetadata(FileItemWidget* widget);
    void sendFileToUser(const QString& username, const QString& fileId);
    void navigateTo(QWidget* newWindow);
};

#endif // SENT_DASH_H