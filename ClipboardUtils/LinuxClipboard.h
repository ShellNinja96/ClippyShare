#ifndef linux_clipbpoard_h
#define linux_clipbpoard_h

/*
#include <string>

std::string GetClipboardContent();
void SetClipboardContent(const std::string& content);
*/

unsigned char* GetClipboardContent();
void SetClipboardContent(const unsigned char* content);
void ClearClipboard();

#endif //linux_clipbpoard_h
