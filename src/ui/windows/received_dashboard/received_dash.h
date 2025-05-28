#ifndef RECEIVED_DASH_H
#define RECEIVED_DASH_H

#include <QWidget>
#include <QListWidgetItem>
#include "../../utils/file_item_widget/file_item_widget.h"
#include "../../utils/window_manager/window_manager.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Received; }
QT_END_NAMESPACE

class Received : public QWidget {
    Q_OBJECT

public:
    explicit Received(QWidget *parent = nullptr, QWidget* sendFileWindow = nullptr);
    ~Received() override;

private slots:
    void onSendButtonClicked();
    void onFileItemClicked(FileItemWidget* widget);
    void onDownloadFileClicked(FileItemWidget* widget);
    void onSentButtonClicked();
    void onSettingsButtonClicked();
    void refreshFileList();
    void onSendFileButtonClicked();
    void onLogoutButtonClicked();
    void onWindowShown(const QString& windowName);

private:
    Ui::Received *ui;
    QWidget* m_sendFileWindow;
    void setupConnections();
    void setupFileList();
    void showFileMetadata(FileItemWidget* widget);
    void sendFileToUser(const QString& username, const QString& fileId);
    void addFileItem(const QString& fileName, 
                    const QString& fileSize, 
                    const QString& timestamp,
                    const QString& owner);
    void navigateTo(QWidget* newWindow);
};

#endif // RECEIVED_DASH_H