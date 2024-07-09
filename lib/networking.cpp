#include "networking.hpp"
#include <cstring>
#include <stdexcept>
#include <iostream>

// CONSTRUCTOR

Socket::Socket(const std::string& executionMode, const char* IPv4, const unsigned short port, const bool& verbose) {

    // Windows specific
    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) throw std::runtime_error("WSAStartup failed.");
    #endif

    // Create socket
    if(verbose) std::cout << "Creating socket...\n";
    firstDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (firstDescriptor < 0) {
        #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
            WSACleanup();
        #endif
        throw std::runtime_error("Failed to create socket.");
    }

    // Structure address
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, IPv4, &address.sin_addr) <= 0) closeSocketThrow(firstDescriptor, "Invalid IPv4 address.");

    // Establish connection
    if (executionMode == "client") {

        // Connect to Socket
        if(verbose) std::cout << "Connecting to server socket...\n";
        connectedDescriptor = firstDescriptor;
        if (connect(connectedDescriptor, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) < 0) closeSocketThrow(connectedDescriptor, "Failed to connect with server socket.");

    } else if (executionMode == "server") {

        // Bind address to socket
        if(verbose) std::cout << "Binding address to socket...\n";
        if (bind(firstDescriptor, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) == -1) closeSocketThrow(firstDescriptor, "Failed to bind address to socket.");

        // Make socket listen
        if (listen(firstDescriptor, SOMAXCONN) == -1) closeSocketThrow(firstDescriptor, "Failed to listen on socket");

        // Accept connection
        if(verbose) std::cout << "Waiting for client connection...\n";
        socklen_t addressLength = sizeof(address);
        connectedDescriptor = accept(firstDescriptor, reinterpret_cast<struct sockaddr*>(&address), &addressLength);
        closeSocket(firstDescriptor);
        if (connectedDescriptor < 0) closeSocketThrow(connectedDescriptor, "Failed to accept connection");
        


    } else closeSocketThrow(firstDescriptor, "Invalid execution mode. Must either be set to 'client' or 'server'.");

    if(verbose) std::cout << "Connection established!\n";

}

// DESTRUCTOR

Socket::~Socket() {

    closeSocket(connectedDescriptor);
    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
        WSACleanup();
    #endif

}

// PRIVATE METHODS

void Socket::closeSocket(socket_t& socketToClose) {

    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
        closesocket(socketToClose);
    #elif defined(__linux__)
        close(socketToClose);
    #endif
    
}

void Socket::closeSocketThrow(socket_t& socketToClose, std::string errorMessage) {

    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
        closesocket(socketToClose);
        WSACleanup();
    #elif defined(__linux__)
        close(socketToClose);
    #endif

    throw std::runtime_error(errorMessage);
}

// PUBLIC METHODS

int Socket::getBufferSize() {
    return bufferSize;
}

void Socket::sendData(std::string data) {

    const char* dataToSend = data.c_str();
    int dataSize = data.size();
    if (send(connectedDescriptor, dataToSend, dataSize, 0) < 0) closeSocketThrow(connectedDescriptor, "Failed to send data");

}

std::string Socket::receiveData() {

    char* buffer = new char[bufferSize + 1];
    std::memset(buffer, 0, bufferSize + 1);
    int bytesReceived = recv(connectedDescriptor, buffer, bufferSize, 0);
    if (bytesReceived < 0) { delete[] buffer; closeSocketThrow(connectedDescriptor,"Failed to receive data"); }
    buffer[bytesReceived] = '\0';
    std::string data(buffer, bytesReceived);
    delete[] buffer;
    return data;

}