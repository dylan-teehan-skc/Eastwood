//
// Created by Josh Sloggett on 30/05/2025.
//

#ifndef QRCODEGENERATOR_H
#define QRCODEGENERATOR_H
#include <QImage>
#include <QByteArray>
#include <string>

QImage getQRCodeImage(std::string input);

QImage getQRCodeForMyDevicePublicKey(const std::string& public_key_b64);

#endif //QRCODEGENERATOR_H
