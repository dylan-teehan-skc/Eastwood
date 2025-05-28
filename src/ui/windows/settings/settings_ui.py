# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'settings.ui'
##
## Created by: Qt User Interface Compiler version 6.9.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSizePolicy, QSpacerItem, QVBoxLayout,
    QWidget)

from src.ui.utils.navbar.navbar import NavBar

class Ui_Settings(object):
    def setupUi(self, Settings):
        if not Settings.objectName():
            Settings.setObjectName(u"Settings")
        Settings.resize(1000, 700)
        Settings.setMinimumSize(QSize(1000, 700))
        Settings.setStyleSheet(u"background-color: white;")
        self.mainLayout = QHBoxLayout(Settings)
        self.mainLayout.setSpacing(0)
        self.mainLayout.setObjectName(u"mainLayout")
        self.mainLayout.setContentsMargins(0, 0, 0, 0)
        self.navBar = NavBar(Settings)
        self.navBar.setObjectName(u"navBar")
        self.navBar.setMinimumSize(QSize(220, 0))
        self.navBar.setMaximumSize(QSize(220, 16777215))

        self.mainLayout.addWidget(self.navBar)

        self.contentLayout = QVBoxLayout()
        self.contentLayout.setSpacing(20)
        self.contentLayout.setObjectName(u"contentLayout")
        self.contentLayout.setContentsMargins(35, 35, 35, 35)
        self.topSpacer = QSpacerItem(20, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.contentLayout.addItem(self.topSpacer)

        self.pageTitle = QLabel(Settings)
        self.pageTitle.setObjectName(u"pageTitle")
        self.pageTitle.setStyleSheet(u"font-size: 24px; font-weight: bold; color: #2d3436; margin-bottom: 10px;")

        self.contentLayout.addWidget(self.pageTitle)

        self.passphraseWidget = QWidget(Settings)
        self.passphraseWidget.setObjectName(u"passphraseWidget")
        self.passphraseWidget.setMinimumSize(QSize(0, 400))
        self.passphraseWidget.setStyleSheet(u"QWidget#passphraseWidget {\n"
"  background-color: white;\n"
"  border: 1px solid #dfe6e9;\n"
"  border-radius: 12px;\n"
"  padding: 30px;\n"
"}")
        self.passphraseLayout = QVBoxLayout(self.passphraseWidget)
        self.passphraseLayout.setSpacing(20)
        self.passphraseLayout.setObjectName(u"passphraseLayout")
        self.passphraseLayout.setContentsMargins(20, -1, 20, -1)
        self.passphraseSectionTitle = QLabel(self.passphraseWidget)
        self.passphraseSectionTitle.setObjectName(u"passphraseSectionTitle")
        self.passphraseSectionTitle.setStyleSheet(u"font-size: 18px; font-weight: bold; color: #2d3436; margin-bottom: 10px;")

        self.passphraseLayout.addWidget(self.passphraseSectionTitle)

        self.currentPassphraseLabel = QLabel(self.passphraseWidget)
        self.currentPassphraseLabel.setObjectName(u"currentPassphraseLabel")
        self.currentPassphraseLabel.setStyleSheet(u"font-size: 14px; color: #2d3436; font-weight: 500; margin-bottom: 5px;")

        self.passphraseLayout.addWidget(self.currentPassphraseLabel)

        self.currentPassphrase = QLineEdit(self.passphraseWidget)
        self.currentPassphrase.setObjectName(u"currentPassphrase")
        self.currentPassphrase.setMinimumSize(QSize(0, 40))
        self.currentPassphrase.setStyleSheet(u"QLineEdit {\n"
"  padding: 8px 12px;\n"
"  border: 1px solid #dfe6e9;\n"
"  border-radius: 6px;\n"
"  background-color: #f8f9fa;\n"
"  color: #2d3436;\n"
"  font-size: 14px;\n"
"}\n"
"QLineEdit:focus {\n"
"  border: 1px solid #6c5ce7;\n"
"  background-color: white;\n"
"}")
        self.currentPassphrase.setEchoMode(QLineEdit.EchoMode.Password)

        self.passphraseLayout.addWidget(self.currentPassphrase)

        self.newPassphraseLabel = QLabel(self.passphraseWidget)
        self.newPassphraseLabel.setObjectName(u"newPassphraseLabel")
        self.newPassphraseLabel.setStyleSheet(u"font-size: 14px; color: #2d3436; font-weight: 500; margin-bottom: 5px;")

        self.passphraseLayout.addWidget(self.newPassphraseLabel)

        self.newPassphrase = QLineEdit(self.passphraseWidget)
        self.newPassphrase.setObjectName(u"newPassphrase")
        self.newPassphrase.setMinimumSize(QSize(0, 40))
        self.newPassphrase.setStyleSheet(u"QLineEdit {\n"
"  padding: 8px 12px;\n"
"  border: 1px solid #dfe6e9;\n"
"  border-radius: 6px;\n"
"  background-color: #f8f9fa;\n"
"  color: #2d3436;\n"
"  font-size: 14px;\n"
"}\n"
"QLineEdit:focus {\n"
"  border: 1px solid #6c5ce7;\n"
"  background-color: white;\n"
"}")
        self.newPassphrase.setEchoMode(QLineEdit.EchoMode.Password)

        self.passphraseLayout.addWidget(self.newPassphrase)

        self.confirmPassphraseLabel = QLabel(self.passphraseWidget)
        self.confirmPassphraseLabel.setObjectName(u"confirmPassphraseLabel")
        self.confirmPassphraseLabel.setStyleSheet(u"font-size: 14px; color: #2d3436; font-weight: 500; margin-bottom: 5px;")

        self.passphraseLayout.addWidget(self.confirmPassphraseLabel)

        self.confirmPassphrase = QLineEdit(self.passphraseWidget)
        self.confirmPassphrase.setObjectName(u"confirmPassphrase")
        self.confirmPassphrase.setMinimumSize(QSize(0, 40))
        self.confirmPassphrase.setStyleSheet(u"QLineEdit {\n"
"  padding: 8px 12px;\n"
"  border: 1px solid #dfe6e9;\n"
"  border-radius: 6px;\n"
"  background-color: #f8f9fa;\n"
"  color: #2d3436;\n"
"  font-size: 14px;\n"
"}\n"
"QLineEdit:focus {\n"
"  border: 1px solid #6c5ce7;\n"
"  background-color: white;\n"
"}")
        self.confirmPassphrase.setEchoMode(QLineEdit.EchoMode.Password)

        self.passphraseLayout.addWidget(self.confirmPassphrase)

        self.passphraseRequirements = QLabel(self.passphraseWidget)
        self.passphraseRequirements.setObjectName(u"passphraseRequirements")
        self.passphraseRequirements.setStyleSheet(u"font-size: 12px; color: #636e72; margin-top: 5px;")

        self.passphraseLayout.addWidget(self.passphraseRequirements)


        self.contentLayout.addWidget(self.passphraseWidget)

        self.bottomSpacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)

        self.contentLayout.addItem(self.bottomSpacer)

        self.buttonLayout = QHBoxLayout()
        self.buttonLayout.setObjectName(u"buttonLayout")
        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.buttonLayout.addItem(self.horizontalSpacer)

        self.cancelButton = QPushButton(Settings)
        self.cancelButton.setObjectName(u"cancelButton")
        self.cancelButton.setMinimumSize(QSize(130, 44))
        self.cancelButton.setStyleSheet(u"QPushButton {\n"
"  font-size: 14px;\n"
"  font-weight: bold;\n"
"  color: #2d3436;\n"
"  background-color: #dfe6e9;\n"
"  border-radius: 10px;\n"
"  padding: 0 20px;\n"
"}\n"
"QPushButton:hover {\n"
"  background-color: #b2bec3;\n"
"}\n"
"QPushButton:pressed {\n"
"  background-color: #a4b0be;\n"
"}")

        self.buttonLayout.addWidget(self.cancelButton)

        self.saveButton = QPushButton(Settings)
        self.saveButton.setObjectName(u"saveButton")
        self.saveButton.setMinimumSize(QSize(130, 44))
        self.saveButton.setStyleSheet(u"QPushButton {\n"
"  font-size: 14px;\n"
"  font-weight: bold;\n"
"  color: white;\n"
"  background-color: #6c5ce7;\n"
"  border-radius: 10px;\n"
"  padding: 0 20px;\n"
"}\n"
"QPushButton:hover {\n"
"  background-color: #5049c9;\n"
"}\n"
"QPushButton:pressed {\n"
"  background-color: #4040b0;\n"
"}")

        self.buttonLayout.addWidget(self.saveButton)


        self.contentLayout.addLayout(self.buttonLayout)


        self.mainLayout.addLayout(self.contentLayout)


        self.retranslateUi(Settings)

        QMetaObject.connectSlotsByName(Settings)
    # setupUi

    def retranslateUi(self, Settings):
        Settings.setWindowTitle(QCoreApplication.translate("Settings", u"Nightwood - Settings", None))
        self.pageTitle.setText(QCoreApplication.translate("Settings", u"Settings", None))
        self.passphraseSectionTitle.setText(QCoreApplication.translate("Settings", u"Change Passphrase", None))
        self.currentPassphraseLabel.setText(QCoreApplication.translate("Settings", u"Current Passphrase", None))
        self.newPassphraseLabel.setText(QCoreApplication.translate("Settings", u"New Passphrase", None))
        self.confirmPassphraseLabel.setText(QCoreApplication.translate("Settings", u"Confirm New Passphrase", None))
        self.passphraseRequirements.setText(QCoreApplication.translate("Settings", u"Passphrase must be between 20 and 64 characters", None))
        self.cancelButton.setText(QCoreApplication.translate("Settings", u"Cancel", None))
        self.saveButton.setText(QCoreApplication.translate("Settings", u"Save Changes", None))
    # retranslateUi

