#ifndef MESSAGEBOX_H
#define MESSAGEBOX_H

#include <QMessageBox>
#include <QPushButton>
#include <QPixmap>
#include <QInputDialog>
#include <QString>
#include <QDialog>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QLabel>
#include <QHBoxLayout>
#include "src/ui/utils/input_validation/passphrase_validator.h"

class StyledMessageBox {
public:
    // Style a standard message box
    static void applyStyle(QMessageBox* msgBox) {
        if (!msgBox) return;
        
        // Apply stylesheet to the message box
        msgBox->setStyleSheet(
            "QMessageBox {"
            "  background-color: #f5f6fa;"
            "  font-family: 'Helvetica Neue', Arial, sans-serif;"
            "  min-width: 300px;"
            "}"
            "QMessageBox QLabel {"
            "  color: #2d3436;"
            "  font-size: 14px;"
            "  padding: 10px;"
            "}"
            "QMessageBox QPushButton {"
            "  background-color: #6c5ce7;"
            "  color: white;"
            "  border-radius: 6px;"
            "  padding: 8px 16px;"
            "  font-weight: bold;"
            "  min-width: 80px;"
            "  font-size: 13px;"
            "  margin: 5px;"
            "}"
            "QMessageBox QPushButton:hover {"
            "  background-color: #5049c9;"
            "}"
            "QMessageBox QPushButton:pressed {"
            "  background-color: #4040b0;"
            "}"
        );
        
        // Center the message box on the active window
        msgBox->setWindowFlags(Qt::Dialog | Qt::CustomizeWindowHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint);
    }
    
    // Convenience methods for different message types
    static void info(QWidget* parent, const QString& title, const QString& text) {
        QMessageBox msgBox(QMessageBox::Information, title, text, QMessageBox::Ok, parent);
        applyStyle(&msgBox);
        msgBox.exec();
    }
    
    static void warning(QWidget* parent, const QString& title, const QString& text) {
        QMessageBox msgBox(QMessageBox::Warning, title, text, QMessageBox::Ok, parent);
        applyStyle(&msgBox);
        msgBox.exec();
    }
    
    static void error(QWidget* parent, const QString& title, const QString& text) {
        QMessageBox msgBox(QMessageBox::Critical, title, text, QMessageBox::Ok, parent);
        applyStyle(&msgBox);
        msgBox.exec();
    }
    
    static void success(QWidget* parent, const QString& title, const QString& text) {
        QMessageBox msgBox(QMessageBox::Information, title, text, QMessageBox::Ok, parent);
        
        // Apply custom success styling
        msgBox.setStyleSheet(
            "QMessageBox {"
            "  font-family: 'Helvetica Neue', Arial, sans-serif;"
            "  min-width: 300px;"
            "}"
            "QMessageBox QLabel {"
            "  color: #2d3436;"
            "  font-size: 14px;"
            "  padding: 10px;"
            "}"
            "QMessageBox QPushButton {"
            "  background-color: #00b894;"  // Green color
            "  color: white;"
            "  border-radius: 6px;"
            "  padding: 8px 16px;"
            "  font-weight: bold;"
            "  min-width: 80px;"
            "  font-size: 13px;"
            "  margin: 5px;"
            "}"
            "QMessageBox QPushButton:hover {"
            "  background-color: #00a884;"  // Darker green on hover
            "}"
            "QMessageBox QPushButton:pressed {"
            "  background-color: #009874;"  // Even darker green when pressed
            "}"
        );
        
        // Set custom icon
        msgBox.setIconPixmap(QPixmap(":icons/logos/tick.svg").scaled(32, 32, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        
        // Center the message box on the active window
        msgBox.setWindowFlags(Qt::Dialog | Qt::CustomizeWindowHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint);
        msgBox.exec();
    }
    
    static bool question(QWidget* parent, const QString& title, const QString& text) {
        QMessageBox msgBox(QMessageBox::Question, title, text, 
                          QMessageBox::Yes | QMessageBox::No, parent);
        applyStyle(&msgBox);
        
        // Style Yes/No buttons differently
        QList<QAbstractButton*> buttons = msgBox.buttons();
        for (QAbstractButton* button : buttons) {
            if (QPushButton* pushButton = dynamic_cast<QPushButton*>(button)) {
                if (msgBox.buttonRole(pushButton) == QMessageBox::YesRole) {
                    pushButton->setStyleSheet(
                        "background-color: #6c5ce7;"
                        "color: white;"
                    );
                } else if (msgBox.buttonRole(pushButton) == QMessageBox::NoRole) {
                    pushButton->setStyleSheet(
                        "background-color: white;"
                        "color: #6c5ce7;"
                        "border: 2px solid #6c5ce7;"
                    );
                }
            }
        }
        
        return msgBox.exec() == QMessageBox::Yes;
    }
    
    static bool connectionRequest(QWidget* parent, const QString& title, const QString& text, QString& deviceName) {
        QMessageBox msgBox(QMessageBox::Question, title, text, 
                          QMessageBox::Yes | QMessageBox::No, parent);
        applyStyle(&msgBox);
        
        // Style Accept/Deny buttons
        QList<QAbstractButton*> buttons = msgBox.buttons();
        for (QAbstractButton* button : buttons) {
            if (QPushButton* pushButton = dynamic_cast<QPushButton*>(button)) {
                if (msgBox.buttonRole(pushButton) == QMessageBox::YesRole) {
                    pushButton->setText("Accept");
                    pushButton->setStyleSheet(R"(
                        QPushButton {
                            background-color: #27ae60;
                            color: white;
                            border: none;
                        }
                        QPushButton:hover {
                            background-color: #219a52;
                        }
                        QPushButton:pressed {
                            background-color: #1e8449;
                        }
                    )");
                } else if (msgBox.buttonRole(pushButton) == QMessageBox::NoRole) {
                    pushButton->setText("Deny");
                    pushButton->setStyleSheet(R"(
                        QPushButton {
                            background-color: #e74c3c;
                            color: white;
                            border: none;
                        }
                        QPushButton:hover {
                            background-color: #c0392b;
                        }
                        QPushButton:pressed {
                            background-color: #a93226;
                        }
                    )");
                }
            }
        }
        
        if (msgBox.exec() == QMessageBox::Yes) {
            QInputDialog inputDialog(parent);
            inputDialog.setWindowTitle("New Device");
            inputDialog.setLabelText("Enter a name for this device:");
            inputDialog.setTextValue("");
            inputDialog.setStyleSheet(R"(
                QInputDialog {
                    background-color: #f5f6fa;
                    font-family: 'Helvetica Neue', Arial, sans-serif;
                }
                QInputDialog QLabel {
                    color: #2d3436;
                    font-size: 14px;
                    padding: 10px;
                }
                QInputDialog QLineEdit {
                    padding: 8px 12px;
                    font-size: 14px;
                    border-radius: 6px;
                    background-color: white;
                    border: 1px solid #dfe6e9;
                    color: #2d3436;
                    margin: 4px 0;
                    min-height: 20px;
                }
                QInputDialog QLineEdit:focus {
                    border: 2px solid #6c5ce7;
                }
                QInputDialog QPushButton {
                    background-color: #6c5ce7;
                    color: white;
                    border-radius: 6px;
                    padding: 8px 16px;
                    font-weight: bold;
                    min-width: 80px;
                    font-size: 13px;
                    margin: 5px;
                }
                QInputDialog QPushButton:hover {
                    background-color: #5049c9;
                }
                QInputDialog QPushButton:pressed {
                    background-color: #4040b0;
                }
            )");

            bool ok = inputDialog.exec();
            deviceName = inputDialog.textValue();
            
            if (ok && !deviceName.isEmpty()) {
                return true;
            }
            return false;
        }
        return false;
    }

    static bool displayCode(QWidget* parent, const QString& title, const QString& text, QString& auth_code) {
        QDialog dialog(parent);
        dialog.setWindowTitle(title);
        dialog.setMinimumWidth(400);
        dialog.setStyleSheet("QDialog { background-color: #f5f6fa; }");
        
        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        
        // Message label
        QLabel* messageLabel = new QLabel(text, &dialog);
        messageLabel->setStyleSheet("color: #2d3436; font-size: 14px; margin: 10px; font-weight: bold;");
        messageLabel->setWordWrap(true);
        layout->addWidget(messageLabel);
        
        // Auth code display box
        QLineEdit* codeBox = new QLineEdit(auth_code, &dialog);
        codeBox->setReadOnly(true);
        codeBox->setAlignment(Qt::AlignCenter);
        codeBox->setStyleSheet(R"(
            QLineEdit {
                padding: 12px;
                font-size: 24px;
                font-family: 'Courier New', monospace;
                font-weight: bold;
                border-radius: 8px;
                background-color: white;
                border: 2px solid #dfe6e9;
                color: #2d3436;
                margin: 10px;
                letter-spacing: 2px;
            }
        )");
        layout->addWidget(codeBox);
        
        // Close button
        QPushButton* closeButton = new QPushButton("Close", &dialog);
        closeButton->setStyleSheet(R"(
            QPushButton {
                background-color: #6c5ce7;
                color: white;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                min-width: 80px;
                font-size: 13px;
                margin: 10px;
            }
            QPushButton:hover {
                background-color: #5049c9;
            }
            QPushButton:pressed {
                background-color: #4040b0;
            }
        )");
        layout->addWidget(closeButton, 0, Qt::AlignCenter);
        
        QObject::connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        
        dialog.exec();
        return true;
    }
    
    static QString getPassphraseWithVerification(QWidget* parent, QString& errorMessage) {
        QDialog dialog(parent);
        dialog.setWindowTitle("Set Passphrase");
        dialog.setMinimumWidth(400);
        
        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        
        // Passphrase input
        QLabel* passphraseLabel = new QLabel("Enter a passphrase (20-64 characters):", &dialog);
        passphraseLabel->setStyleSheet("color: #2d3436; font-size: 14px; margin-top: 10px;");
        layout->addWidget(passphraseLabel);
        
        QLineEdit* passphraseEdit = new QLineEdit(&dialog);
        passphraseEdit->setEchoMode(QLineEdit::Password);
        passphraseEdit->setStyleSheet(
            "QLineEdit {"
            "  padding: 8px 12px;"
            "  font-size: 14px;"
            "  border-radius: 6px;"
            "  background-color: white;"
            "  border: 1px solid #dfe6e9;"
            "  color: #2d3436;"
            "  margin: 4px 0;"
            "}"
            "QLineEdit:focus {"
            "  border: 2px solid #6c5ce7;"
            "}"
        );
        layout->addWidget(passphraseEdit);
        
        // Verify passphrase input
        QLabel* verifyLabel = new QLabel("Enter the passphrase again:", &dialog);
        verifyLabel->setStyleSheet("color: #2d3436; font-size: 14px; margin-top: 10px;");
        layout->addWidget(verifyLabel);
        
        QLineEdit* verifyEdit = new QLineEdit(&dialog);
        verifyEdit->setEchoMode(QLineEdit::Password);
        verifyEdit->setStyleSheet(passphraseEdit->styleSheet());
        layout->addWidget(verifyEdit);
        
        // Error label
        QLabel* errorLabel = new QLabel(&dialog);
        errorLabel->setStyleSheet("color: #e74c3c; font-size: 12px; margin-top: 5px;");
        errorLabel->setWordWrap(true);
        errorLabel->hide();
        layout->addWidget(errorLabel);
        
        // Buttons
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        buttonLayout->addStretch();
        
        QPushButton* cancelButton = new QPushButton("Cancel", &dialog);
        cancelButton->setStyleSheet(
            "QPushButton {"
            "  background-color: #dfe6e9;"
            "  color: #2d3436;"
            "  border-radius: 6px;"
            "  padding: 8px 16px;"
            "  font-weight: bold;"
            "  min-width: 80px;"
            "  font-size: 13px;"
            "  margin: 5px;"
            "}"
            "QPushButton:hover {"
            "  background-color: #b2bec3;"
            "}"
            "QPushButton:pressed {"
            "  background-color: #a4b0be;"
            "}"
        );
        
        QPushButton* okButton = new QPushButton("OK", &dialog);
        okButton->setStyleSheet(
            "QPushButton {"
            "  background-color: #6c5ce7;"
            "  color: white;"
            "  border-radius: 6px;"
            "  padding: 8px 16px;"
            "  font-weight: bold;"
            "  min-width: 80px;"
            "  font-size: 13px;"
            "  margin: 5px;"
            "}"
            "QPushButton:hover {"
            "  background-color: #5049c9;"
            "}"
            "QPushButton:pressed {"
            "  background-color: #4040b0;"
            "}"
        );
        
        buttonLayout->addWidget(cancelButton);
        buttonLayout->addWidget(okButton);
        layout->addLayout(buttonLayout);
        
        // Connect buttons
        QObject::connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);
        QObject::connect(okButton, &QPushButton::clicked, [&]() {
            QString passphrase = passphraseEdit->text();
            QString verifyPassphrase = verifyEdit->text();
            
            QString validationError;
            if (!PassphraseValidator::validate(passphrase, verifyPassphrase, validationError)) {
                errorLabel->setText(validationError);
                errorLabel->show();
                return;
            }
            
            dialog.accept();
        });
        
        // Show dialog
        if (dialog.exec() == QDialog::Accepted) {
            errorMessage = QString();
            return passphraseEdit->text();
        }
        
        errorMessage = "Passphrase entry cancelled";
        return QString();
    }

    static QString getUsername(QWidget* parent, QString& errorMessage) {
        QDialog dialog(parent);
        dialog.setWindowTitle("Enter Username");
        dialog.setMinimumWidth(400);
        
        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        
        // Username input
        QLabel* usernameLabel = new QLabel("Enter username:", &dialog);
        usernameLabel->setStyleSheet("color: #2d3436; font-size: 14px; margin-top: 10px;");
        layout->addWidget(usernameLabel);
        
        QLineEdit* usernameEdit = new QLineEdit(&dialog);
        usernameEdit->setStyleSheet(
            "QLineEdit {"
            "  padding: 8px 12px;"
            "  font-size: 14px;"
            "  border-radius: 6px;"
            "  background-color: white;"
            "  border: 1px solid #dfe6e9;"
            "  color: #2d3436;"
            "  margin: 4px 0;"
            "}"
            "QLineEdit:focus {"
            "  border: 2px solid #6c5ce7;"
            "}"
        );
        layout->addWidget(usernameEdit);
        
        // Error label
        QLabel* errorLabel = new QLabel(&dialog);
        errorLabel->setStyleSheet("color: #e74c3c; font-size: 12px; margin-top: 5px;");
        errorLabel->setWordWrap(true);
        errorLabel->hide();
        layout->addWidget(errorLabel);
        
        // Buttons
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        buttonLayout->addStretch();
        
        QPushButton* cancelButton = new QPushButton("Cancel", &dialog);
        cancelButton->setStyleSheet(
            "QPushButton {"
            "  background-color: #dfe6e9;"
            "  color: #2d3436;"
            "  border-radius: 6px;"
            "  padding: 8px 16px;"
            "  font-weight: bold;"
            "  min-width: 80px;"
            "  font-size: 13px;"
            "  margin: 5px;"
            "}"
            "QPushButton:hover {"
            "  background-color: #b2bec3;"
            "}"
            "QPushButton:pressed {"
            "  background-color: #a4b0be;"
            "}"
        );
        
        QPushButton* okButton = new QPushButton("OK", &dialog);
        okButton->setStyleSheet(
            "QPushButton {"
            "  background-color: #6c5ce7;"
            "  color: white;"
            "  border-radius: 6px;"
            "  padding: 8px 16px;"
            "  font-weight: bold;"
            "  min-width: 80px;"
            "  font-size: 13px;"
            "  margin: 5px;"
            "}"
            "QPushButton:hover {"
            "  background-color: #5049c9;"
            "}"
            "QPushButton:pressed {"
            "  background-color: #4040b0;"
            "}"
        );
        
        buttonLayout->addWidget(cancelButton);
        buttonLayout->addWidget(okButton);
        layout->addLayout(buttonLayout);
        
        // Connect buttons
        QObject::connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);
        QObject::connect(okButton, &QPushButton::clicked, [&]() {
            QString username = usernameEdit->text().trimmed();
            
            if (username.isEmpty()) {
                errorLabel->setText("Username is required");
                errorLabel->show();
                return;
            }
            
            dialog.accept();
        });
        
        // Show dialog
        if (dialog.exec() == QDialog::Accepted) {
            errorMessage = QString();
            return usernameEdit->text().trimmed();
        }
        
        errorMessage = "Username entry cancelled";
        return QString();
    }
};

#endif // MESSAGEBOX_H 