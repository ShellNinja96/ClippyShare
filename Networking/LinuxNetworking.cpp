#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "LinuxNetworking.h"

int CreateIPv4TCPSocket() {
    int fileDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (fileDescriptor < 0) throw std::runtime_error("Socket creation failed");
    return fileDescriptor;
}

sockaddr_in StructIPv4SocketAddress(const char* serverIPv4, const unsigned short& port) {
    sockaddr_in address;
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, serverIPv4, &address.sin_addr) <= 0)
        throw std::runtime_error("Invalid address/ Address not supported");
    address.sin_port = htons(port);
    return address;
}

void BindAddressToSocket(const int& socketFileDescriptor, const sockaddr_in& socketAddress) {
    if (bind(socketFileDescriptor, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0)
        throw std::runtime_error("Failed to bind address to socket");
}

void MakeSocketListen(const int& socketFileDescriptor) {
    if (listen(socketFileDescriptor, 3) < 0)
        throw std::runtime_error("Failed to change socket status to Listening");
}

int AcceptConnection(const int& serverSocket, sockaddr_in& serverSocketAddress) {
    socklen_t serverSocketAddressLength = sizeof(serverSocketAddress);
    int clientSocket = accept(serverSocket, (sockaddr*)&serverSocketAddress, &serverSocketAddressLength);
    if (clientSocket < 0) throw std::runtime_error("Failed to accept client connection");
    return clientSocket; 
}

void ConnectToSocket(const int& clientSocketFileDescriptor, const sockaddr_in& serverSocketAddress) {
    if (connect(clientSocketFileDescriptor, (struct sockaddr*)&serverSocketAddress, sizeof(serverSocketAddress)) < 0) throw std::runtime_error("Failed to connect to server");
}
