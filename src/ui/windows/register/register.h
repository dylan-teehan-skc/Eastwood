#ifndef REGISTER_H
#define REGISTER_H

#include <QWidget>
#include "src/ui/utils/input_validation/passphrase_validator.h"
#include "src/ui/utils/input_validation/name_validator.h"

namespace Ui {
class Register;
}

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
    void onRegistrationSuccess() const;
    void onRegistrationError(const QString& title, const QString& message);

private:
    void setupConnections();
    Ui::Register *ui;
    QWidget* m_loginWindow = nullptr;
    bool m_passphraseVisible = false;
};

#endif // REGISTER_H 