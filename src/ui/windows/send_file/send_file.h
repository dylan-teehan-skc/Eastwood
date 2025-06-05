#ifndef SEND_FILE_H
#define SEND_FILE_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QFileDialog>

QT_BEGIN_NAMESPACE
namespace Ui { class SendFile; }
QT_END_NAMESPACE

class SendFile : public QWidget {
    Q_OBJECT

public:
    explicit SendFile(QWidget *parent = nullptr);
    ~SendFile() override;

private slots:
    void onBrowseClicked();
    void onSendClicked();
    void onReceivedButtonClicked() const;
    void onSentButtonClicked() const;
    void onSendFileButtonClicked() const;
    void onSettingsButtonClicked() const;
    void onShowAuthCodeClicked();

private:
    Ui::SendFile *ui;
    void setupConnections();
    void navigateTo(QWidget* newWindow);
};

#endif // SEND_FILE_H