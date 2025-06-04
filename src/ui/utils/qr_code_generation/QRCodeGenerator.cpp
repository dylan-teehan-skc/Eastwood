//
// Created by Josh Sloggett on 30/05/2025.
//

#include "QRCodeGenerator.h"

#include <qrcodegen.hpp>
#include <sstream>

#include "src/sql/queries.h"

std::string toSvgString(const qrcodegen::QrCode &qr, int border) {
    if (border < 0)
        throw std::invalid_argument("Border must be non-negative");
    std::ostringstream sb;
    int size = qr.getSize();
    sb << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    sb << "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 "
       << (size + border * 2) << " " << (size + border * 2) << "\" stroke=\"none\">\n";
    sb << "\t<rect width=\"" << (size + border * 2) << "\" height=\"" << (size + border * 2)
       << "\" fill=\"#FFFFFF\"/>\n";
    sb << "\t<path d=\"";
    for (int y = 0; y < size; y++) {
        for (int x = 0; x < size; x++) {
            if (qr.getModule(x, y)) {
                if (x != 0 || y != 0)
                    sb << " ";
                sb << "M" << (x + border) << "," << (y + border) << "h1v1h-1z";
            }
        }
    }
    sb << "\" fill=\"#000000\"/>\n";
    sb << "</svg>\n";
    return sb.str();
}

QImage qrCodeToImage(const qrcodegen::QrCode &qr, int scale = 10) {
    int size = qr.getSize();
    QImage image(size * scale, size * scale, QImage::Format_RGB32);
    image.fill(Qt::white);

    for (int y = 0; y < size; y++) {
        for (int x = 0; x < size; x++) {
            if (qr.getModule(x, y)) {
                for (int sy = 0; sy < scale; sy++) {
                    for (int sx = 0; sx < scale; sx++) {
                        image.setPixel(x * scale + sx, y * scale + sy, qRgb(108, 92, 231)); // #6c5ce7
                    }
                }
            }
        }
    }
    return image;
}

QImage getQRCodeImage(std::string input) {
    qrcodegen::QrCode qr0 = qrcodegen::QrCode::encodeText(input.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    return qrCodeToImage(qr0, 10);
}

QImage getQRCodeForMyDevicePublicKey(const std::string& public_key_b64) {

    std::string input = public_key_b64;
    if (input.back() != '\0') {
        input += '\0';
    }
    
    // Generate QR code with base64 string
    qrcodegen::QrCode qr0 = qrcodegen::QrCode::encodeText(input.c_str(), qrcodegen::QrCode::Ecc::HIGH);
    return qrCodeToImage(qr0, 10);
}

