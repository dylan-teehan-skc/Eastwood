#include "passphrase_validator.h"

namespace PassphraseValidator {
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

        // (all printable ASCII allowed)
        for (const QChar& c : passphrase) {
            if (c.unicode() < 32 || c.unicode() > 126) {
                errorMessage = "Passphrase can only contain ASCII characters";
                return false;
            }
        }

        return true;
    }
} 