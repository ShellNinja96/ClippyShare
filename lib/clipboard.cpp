#include "clipboard.hpp"
#include <string>

void setClipboard(std::string text) {

    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)

        if (OpenClipboard(nullptr)) {

            EmptyClipboard();
            HGLOBAL hGlob = GlobalAlloc(GMEM_FIXED, text.size() + 1);

            if (hGlob != nullptr) {
                memcpy(GlobalLock(hGlob), text.c_str(), text.size() + 1);
                GlobalUnlock(hGlob);
                SetClipboardData(CF_TEXT, hGlob);
            } else throw std::runtime_error("GlobalAlloc failed. getClipboard failed.");

            CloseClipboard();

        } else throw std::runtime_error("Failed to open clipboard.");

    #endif

    #if defined(__linux__)

        std::string command = "echo \"" + text + "\" | xsel --clipboard --input --trim";
        system(command.c_str());

    #endif

}

std::string getClipboard() {

    std::string text;

    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)

        if (OpenClipboard(nullptr)) {

            HANDLE hData = GetClipboardData(CF_TEXT);

            if (hData != nullptr) {
                char* pszText = static_cast<char*>(GlobalLock(hData));

                if (pszText != nullptr) {

                    text = pszText;
                    GlobalUnlock(hData);

                } else throw std::runtime_error("GlobalLock failed. getClipboard failed.");

            } else throw std::runtime_error("GetClipboardData failed.");

            CloseClipboard();

        } else throw std::runtime_error("Failed to open clipboard.");

    #endif

    #if defined(__linux__)

        FILE* stream = popen("xsel --clipboard 2>/dev/null", "r");
        if (stream) {
            char buffer[65000];
            while (fgets(buffer, 65000, stream) != nullptr) text += buffer;
            pclose(stream);
            text.erase(std::find_if(text.rbegin(), text.rend(), [](unsigned char noChar) { return !std::isspace(noChar); }).base(), text.end());
        }

    #endif

    return text;

}
