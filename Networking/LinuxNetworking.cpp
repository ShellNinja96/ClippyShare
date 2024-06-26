#include <cstring>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include "LinuxNetworking.h"

int CreateIPv4TCPSocket() {
    int fileDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (fileDescriptor < 0) throw std::runtime_error("Socket creation failed.");
    return fileDescriptor;
}

sockaddr_in StructIPv4SocketAddress(const char* serverIPv4, const unsigned short& port) {
    sockaddr_in address;
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, serverIPv4, &address.sin_addr) <= 0)
        throw std::runtime_error("Invalid IPv4 address.");
    address.sin_port = htons(port);
    return address;
}

void BindAddressToSocket(const int& socketFileDescriptor, const sockaddr_in& socketAddress) {
    if (bind(socketFileDescriptor, (struct sockaddr *)&socketAddress, sizeof(socketAddress)) < 0)
        throw std::runtime_error("Failed to bind address to socket.");
}

void MakeSocketListen(const int& socketFileDescriptor) {
    if (listen(socketFileDescriptor, 3) < 0) throw std::runtime_error("Failed to change socket status to Listening.");
}

int AcceptConnection(const int& serverSocket, sockaddr_in& serverSocketAddress) {
    socklen_t serverSocketAddressLength = sizeof(serverSocketAddress);
    int clientSocket = accept(serverSocket, (sockaddr*)&serverSocketAddress, &serverSocketAddressLength);
    if (clientSocket < 0) throw std::runtime_error("Failed to accept client connection.");
    return clientSocket; 
}

void ConnectToSocket(const int& clientSocketFileDescriptor, const sockaddr_in& serverSocketAddress) {
    if (connect(clientSocketFileDescriptor, (struct sockaddr*)&serverSocketAddress, sizeof(serverSocketAddress)) < 0) throw std::runtime_error("Failed to connect to server.");
}

void SendData(const int& sendingSocketFileDescriptor, const void* sendBuffer, unsigned long& sendBufferLength) {
    if (send(sendingSocketFileDescriptor, sendBuffer, sendBufferLength, 0) <= 0) throw std::runtime_error("Failed to send data.");
}

void ReceiveData(const int& receivingSocketFileDescriptor, void* receiveBuffer, unsigned long& receiveBufferLength) {
    if (recv(receivingSocketFileDescriptor, receiveBuffer, receiveBufferLength, 0) <= 0 ) throw std::runtime_error("Failed to receive data.");
}

void ReadHostSendData(const int& socketFileDescriptor) {
    
    const char* sendBuffer;
    std::string message;
    unsigned long sendBufferLength;
    
    while(true) {

        std::cout << "Write a message: ";
        std::getline(std::cin, message);
        sendBuffer = message.c_str();
        sendBufferLength = strlen(sendBuffer);
        SendData(socketFileDescriptor, sendBuffer, sendBufferLength);
        std::cout << "Sent     -> " << sendBuffer << std::endl;

    }

}

void ReceiveDataWriteHost(const int& socketFileDescriptor) {

    while(true) {

        char receiveBuffer[1024] = {0};
        unsigned long receiveBufferSize = sizeof(receiveBuffer);
        ReceiveData(socketFileDescriptor, receiveBuffer, receiveBufferSize);
        std::cout << "Received <- " << receiveBuffer << std::endl;

    }

}
