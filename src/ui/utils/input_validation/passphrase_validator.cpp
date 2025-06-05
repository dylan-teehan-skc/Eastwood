#include "passphrase_validator.h"
#include <QFile>
#include <QTextStream>
#include <QSet>
#include <QDir>

namespace PassphraseValidator {
    static QSet<QString> commonPasswords;

    static bool initializeCommonPasswords() {
        if (!commonPasswords.isEmpty()) {
            return true;
        }

        QFile file("src/ui/utils/commons_pass_8_or_more.csv");
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            return false;
        }

        QTextStream in(&file);
        in.readLine(); // Skip header
        
        while (!in.atEnd()) {
            QString line = in.readLine();
            QStringList parts = line.split(',');
            if (!parts.isEmpty()) {
                commonPasswords.insert(parts[0]);
            }
        }

        return true;
    }

    bool validate(const QString& passphrase, const QString& confirmPassphrase, QString& errorMessage) {
        if (passphrase.isEmpty()) {
            errorMessage = "Passphrase is required";
            return false;
        }

        if (passphrase.length() < MIN_PASSPHRASE_LENGTH) {
            errorMessage = QString("Passphrase must be at least %1 characters long").arg(MIN_PASSPHRASE_LENGTH);
            return false;
        }

        if (passphrase.length() > MAX_PASSPHRASE_LENGTH) {
            errorMessage = QString("Passphrase cannot be longer than %1 characters").arg(MAX_PASSPHRASE_LENGTH);
            return false;
        }

        if (confirmPassphrase.isEmpty()) {
            errorMessage = "Please verify your passphrase";
            return false;
        }

        if (passphrase != confirmPassphrase) {
            errorMessage = "Passphrases do not match";
            return false;
        }

        // Check for repetitive characters (3 or more same characters in a row)
        for (int i = 0; i < passphrase.length() - 2; i++) {
            if (passphrase[i] == passphrase[i + 1] && passphrase[i] == passphrase[i + 2]) {
                errorMessage = "Passphrase cannot contain 3 or more of the same character in a row";
                return false;
            }
        }

        // Check for spaces at start/end
        if (passphrase.startsWith(' ') || passphrase.endsWith(' ')) {
            errorMessage = "Passphrase cannot start or end with spaces";
            return false;
        }

        // (all printable ASCII allowed)
        for (const QChar& c : passphrase) {
            if (c.unicode() < 32 || c.unicode() > 126) {
                errorMessage = "Passphrase can only contain printable ASCII characters";
                return false;
            }
        }

        // Check against common passwords
        if (initializeCommonPasswords() && commonPasswords.contains(passphrase)) {
            errorMessage = "This passphrase is too common and not allowed";
            return false;
        }

        return true;
    }
} 