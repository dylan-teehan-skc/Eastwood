#ifndef NAME_VALIDATOR_H
#define NAME_VALIDATOR_H

#include <QString>

namespace NameValidator {
    // Constants
    constexpr int MAX_USERNAME_LENGTH = 32;
    constexpr int MIN_USERNAME_LENGTH = 3;
    constexpr int MAX_FULL_NAME_LENGTH = 64;
    constexpr int MIN_FULL_NAME_LENGTH = 3;

    bool validateUsername(const QString& username, QString& errorMessage);
    bool validateFullName(const QString& fullName, QString& errorMessage);
}

#endif // NAME_VALIDATOR_H 