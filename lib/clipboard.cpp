#include "clipboard.hpp"

Clipboard::Clipboard() {

    #if defined(__linux__)

        display = XOpenDisplay(nullptr);
        if (display == nullptr) throw std::runtime_error("Could not open X display.");
        thisWindow = XCreateSimpleWindow(display, DefaultRootWindow(display), 0, 0, 1, 1, 0, 0, 0);
        clipboardAtom = XInternAtom(display, "CLIPBOARD", False);
        utf8Atom = XInternAtom(display, "UTF8_STRING", False);
        targetsAtom = XInternAtom(display, "TARGETS", False);
        dataReady = false;

    #endif

}

Clipboard::~Clipboard() {

    #if defined(__linux__)

        XCloseDisplay(display);

    #endif

}

void Clipboard::set(std::string text) {

    #if defined(__linux__)

        std::lock_guard<std::mutex> lock(mutex);
        content = text;
        dataReady = true;
        conditionVariable.notify_all();
        XSetSelectionOwner(display, clipboardAtom, thisWindow, CurrentTime);
        if (XGetSelectionOwner(display, clipboardAtom) != thisWindow) throw std::runtime_error("Failed to set clipboard owner.");

    #endif

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

}

std::string Clipboard::get() {

    #if defined(__linux__)

        std::unique_lock<std::mutex> lock(mutex);
        Window owner = XGetSelectionOwner(display, clipboardAtom);
        if (owner == None) throw std::runtime_error("No clipboard owner.");
        if (owner != thisWindow) {

            XConvertSelection(display, clipboardAtom, utf8Atom, clipboardAtom, thisWindow, CurrentTime);
            conditionVariable.wait(lock, [this]{ return dataReady; });
            dataReady = false;

        }

        return content;

    #endif

    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)

        std::string result;

        if (OpenClipboard(nullptr)) {

            HANDLE hData = GetClipboardData(CF_TEXT);

            if (hData != nullptr) {
                char* pszText = static_cast<char*>(GlobalLock(hData));

                if (pszText != nullptr) {

                    result = pszText;
                    GlobalUnlock(hData);

                } else throw std::runtime_error("GlobalLock failed. getClipboard failed.");

            } else throw std::runtime_error("GetClipboardData failed.");

            CloseClipboard();

        } else throw std::runtime_error("Failed to open clipboard.");

        return result;

    #endif

}

#if defined(__linux__)

    void Clipboard::eventHandler() {

        XEvent event;
        while(true) {

            if (XPending(display) > 0) {

                XNextEvent(display, &event);
                std::lock_guard<std::mutex> lock(mutex);

                if (event.type == SelectionRequest) {

                    XSelectionRequestEvent *req = &event.xselectionrequest;
                    XSelectionEvent resp = {0};
                    resp.type = SelectionNotify;
                    resp.display = req->display;
                    resp.requestor = req->requestor;
                    resp.selection = req->selection;
                    resp.time = req->time;
                    resp.target = req->target;
                    resp.property = req->property;

                    if (req->target == utf8Atom) {

                        XChangeProperty(display, req->requestor, req->property, utf8Atom, 8, PropModeReplace, reinterpret_cast<const unsigned char*>(content.c_str()), content.size());

                    } else if (req->target == targetsAtom) {

                        Atom supportedTargets[] = {utf8Atom, targetsAtom};
                        XChangeProperty(display, req->requestor, req->property, XA_ATOM, 32, PropModeReplace, reinterpret_cast<const unsigned char*>(supportedTargets), 2);

                    } else resp.property = None;

                    XSendEvent(display, req->requestor, False, 0, reinterpret_cast<XEvent *>(&resp));
                    XFlush(display);

                } else if (event.type == SelectionNotify) {

                    if (event.xselection.property) {

                        Atom type;
                        int format;
                        unsigned long numItems, bytesAfter;
                        unsigned char *data = nullptr;

                        if (XGetWindowProperty(display, thisWindow, clipboardAtom, 0, ~0L, False, AnyPropertyType, &type, &format, &numItems, &bytesAfter, &data) == Success) {

                            if (data) {

                                content.assign(reinterpret_cast<char*>(data), numItems);
                                XFree(data);
                                dataReady = true;
                                conditionVariable.notify_all();

                            }

                        }

                    }

                }

            }

            std::this_thread::sleep_for(std::chrono::milliseconds(10));  // Reduce CPU usage
            
        }

    }

#endif