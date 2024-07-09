#ifndef CLIPBOARD
#define CLIPBOARD

#include <string>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    #include <windows.h>
    #include <stdexcept>
#endif

#if defined(__linux__)
    #include <algorithm>
#endif

void setClipboard(std::string data);
std::string getClipboard();

#endif // CLIPBOARD