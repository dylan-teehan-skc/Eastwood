#include "byte_converter.h"
#include <cmath>
#include <sstream>
#include <iomanip>

std::string convertFileSizeToHumanReadable(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB"};
    int unitIndex = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unitIndex < 6) {
        size /= 1024.0;
        unitIndex++;
    }
    
    std::stringstream ss;
    if (unitIndex == 0) {
        ss << static_cast<int>(size) << units[unitIndex];
    } else {
        ss << std::fixed << std::setprecision(2) << size << units[unitIndex];
    }
    
    return ss.str();
}
