#ifndef MESSAGEBOX_H
#define MESSAGEBOX_H

#include <QMessageBox>
#include <QPushButton>
#include <QApplication>
#include <QStyle>

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
    
    static bool question(QWidget* parent, const QString& title, const QString& text) {
        QMessageBox msgBox(QMessageBox::Question, title, text, 
                          QMessageBox::Yes | QMessageBox::No, parent);
        applyStyle(&msgBox);
        
        // Style Yes/No buttons differently
        QList<QAbstractButton*> buttons = msgBox.buttons();
        for (QAbstractButton* button : buttons) {
            QPushButton* pushButton = dynamic_cast<QPushButton*>(button);
            if (pushButton) {
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
};

#endif // MESSAGEBOX_H 