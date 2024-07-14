#ifndef CLIPBOARD
#define CLIPBOARD

#include <string>
#include <stdexcept>

#if defined(__linux__)

    #include <X11/Xlib.h>
    #include <X11/Xatom.h>
    #include <thread>
    #include <mutex>
    #include <condition_variable>

#endif

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)

    #include <windows.h>
    
#endif

class Clipboard {
private:

    #if defined(__linux__)

        Atom clipboardAtom, utf8Atom, targetsAtom;
        Display *display;
        Window thisWindow;
        std::string content;
        std::mutex mutex;
        std::condition_variable conditionVariable;
        bool dataReady;

    #endif

public:

    Clipboard();
    ~Clipboard();

    void set(std::string text);
    std::string get();

    #if defined(__linux__)

        void eventHandler();

    #endif

};

#endif // CLIPBOARD