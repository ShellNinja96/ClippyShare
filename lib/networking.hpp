#ifndef NETWORKING
#define NETWORKING

#include <string>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
#endif

#if defined(__linux__)
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    typedef int socket_t;
#endif

class Socket {
private:
    socket_t firstDescriptor, connectedDescriptor;
    sockaddr_in address;
    const int bufferSize = 65000;

    void closeSocket(socket_t& socketToClose);
    void closeSocketThrow(socket_t& socketToClose, std::string errorMessage);

public:

    Socket(const std::string& executionMode, const char* IPv4, const unsigned short port, const bool& verbose);
    ~Socket();
    int getBufferSize();
    void sendData(std::string data);
    std::string receiveData();

};

#endif // NETWORKING