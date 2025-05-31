//
// Created by Josh Sloggett on 30/05/2025.
//

#ifndef QRCODEGENERATOR_H
#define QRCODEGENERATOR_H
#include <QImage>

QImage getQRCodeImage(std::string input);

QImage getQRCodeForMyDevicePublicKey();

#endif //QRCODEGENERATOR_H
