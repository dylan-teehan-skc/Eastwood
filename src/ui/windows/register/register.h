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

signals:
    void registrationSuccess();
    void registrationError(const QString& title, const QString& message);

private slots:
    void onRegisterButtonClicked();
    void onLoginButtonClicked();
    void onTogglePassphraseClicked();
    void onRegistrationSuccess();
    void onRegistrationError(const QString& title, const QString& message);

private:
    Ui::Register *ui;
    void setupConnections();
    QWidget* m_loginWindow = nullptr;
    bool m_passphraseVisible = false;
};

#endif // REGISTER_H 