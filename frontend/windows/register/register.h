#ifndef REGISTER_H
#define REGISTER_H

#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class Register; }
QT_END_NAMESPACE

class Register : public QWidget {
    Q_OBJECT

public:
    explicit Register(QWidget *parent = nullptr);
    ~Register() override;
    
    void setLoginWindow(QWidget* loginWindow) {
        m_loginWindow = loginWindow;
    }

private slots:
    void onRegisterButtonClicked();
    void onLoginButtonClicked();

private:
    Ui::Register *ui;
    void setupConnections();
    QWidget* m_loginWindow = nullptr; // Store the login window
};

#endif // REGISTER_H 