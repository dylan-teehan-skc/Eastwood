
#ifndef UTILS_H
#define UTILS_H
#include <QDebug>

inline QDebug operator<<(QDebug debug, const std::string& str) {
    debug << QString::fromStdString(str);
    return debug;
}

#endif //UTILS_H
