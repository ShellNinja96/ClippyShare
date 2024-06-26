#include <algorithm>
#include <string>

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
