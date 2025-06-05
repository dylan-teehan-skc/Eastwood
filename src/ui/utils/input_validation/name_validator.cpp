#include "name_validator.h"

namespace NameValidator {
    bool validateUsername(const QString& username, QString& errorMessage) {
        QString trimmedUsername = username.trimmed();
        
        if (trimmedUsername.isEmpty()) {
            errorMessage = "Username is required";
            return false;
        }

        if (trimmedUsername.length() < MIN_USERNAME_LENGTH) {
            errorMessage = QString("Username must be at least %1 characters long").arg(MIN_USERNAME_LENGTH);
            return false;
        }

        if (trimmedUsername.length() > MAX_USERNAME_LENGTH) {
            errorMessage = QString("Username cannot be longer than %1 characters").arg(MAX_USERNAME_LENGTH);
            return false;
        }

        // Check for spaces at start/end
        if (username.startsWith(' ') || username.endsWith(' ')) {
            errorMessage = "Username cannot start or end with spaces";
            return false;
        }

        // (all printable ASCII allowed, including spaces)
        for (const QChar& c : username) {
            if (c.unicode() == 32 || (c.unicode() >= 33 && c.unicode() <= 126)) {
                continue;
            }
            errorMessage = "Username can only contain ASCII characters";
            return false;
        }

        return true;
    }

    bool validateFullName(const QString& fullName, QString& errorMessage) {
        QString trimmedFullName = fullName.trimmed();
        
        if (trimmedFullName.isEmpty()) {
            errorMessage = "Full name is required";
            return false;
        }

        if (trimmedFullName.length() < MIN_FULL_NAME_LENGTH) {
            errorMessage = QString("Full name must be at least %1 characters long").arg(MIN_FULL_NAME_LENGTH);
            return false;
        }

        if (trimmedFullName.length() > MAX_FULL_NAME_LENGTH) {
            errorMessage = QString("Full name cannot be longer than %1 characters").arg(MAX_FULL_NAME_LENGTH);
            return false;
        }

        // (all printable ASCII allowed)
        for (const QChar& c : trimmedFullName) {
            if (c.unicode() < 32 || c.unicode() > 126) {
                errorMessage = "Full name can only contain printable characters";
                return false;
            }
        }

        return true;
    }
} 