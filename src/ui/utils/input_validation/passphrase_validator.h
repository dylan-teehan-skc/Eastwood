#ifndef PASSPHRASE_VALIDATOR_H
#define PASSPHRASE_VALIDATOR_H

#include <QString>

namespace PassphraseValidator {
    constexpr int MAX_PASSPHRASE_LENGTH = 64;
    constexpr int MIN_PASSPHRASE_LENGTH = 20;
    bool validate(const QString& passphrase, const QString& confirmPassphrase, QString& errorMessage);
}

#endif // PASSPHRASE_VALIDATOR_H 