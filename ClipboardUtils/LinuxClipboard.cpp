#include "LinuxClipboard.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cctype>

#include <iostream>
#include <string>

/*
std::string GetClipboardContent() {

std::string clipboardContent;
    FILE *stream = popen("xsel --clipboard 2>/dev/null", "r");
    if (stream) {
        char buffer[4096];
        while (fgets(buffer, 4096, stream) != NULL) clipboardContent.append(buffer);
        pclose(stream);
    }
    clipboardContent.erase(std::find_if(clipboardContent.rbegin(), clipboardContent.rend(), [](unsigned char noChar) {
        return !std::isspace(noChar);
    }).base(), clipboardContent.end());
    return clipboardContent;

}

void SetClipboardContent(const std::string& content) {

    std::string command = "echo \"" + content + "\" | xsel --clipboard --input";
    system(command.c_str());

}
*/

unsigned char* GetClipboardContent() {

    unsigned char* clipboardContent = nullptr;

    FILE* stream = popen("xsel --clipboard 2>/dev/null", "r");
    if (stream) {
        char buffer[4096];
        std::string content;
        while (fgets(buffer, 4096, stream) != NULL) content.append(buffer);
        pclose(stream);
        content.erase(std::find_if(content.rbegin(), content.rend(), [](unsigned char noChar) { return !std::isspace(noChar); }).base(), content.end());
        clipboardContent = new unsigned char[content.size() + 1];
        std::memcpy(clipboardContent, content.c_str(), content.size() + 1);
    }

    return clipboardContent;

}

void SetClipboardContent(const unsigned char* content) {

    std::string command = "echo \"" + std::string(reinterpret_cast<const char*>(content)) + "\" | xsel --clipboard --input";
    system(command.c_str());
    std::cout << "Executed SetClipboardContent();\n";

}

void ClearClipboard() {

    std::string command = "echo \"\" | xsel --clipboard --input";
    system(command.c_str());
    std::cout << "Executed ClearClipboard();\n";
}
