#ifndef linux_clipbpoard_h
#define linux_clipbpoard_h

#include <string>
std::string GetClipboardContent();
void SetClipboardContent(const std::string& content);

#endif //linux_clipbpoard_h
