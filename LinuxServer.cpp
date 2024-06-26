#include <cstring>
#include <unistd.h>
#include "Networking/LinuxNetworking.h"
#include <iostream>
#include <thread>

void ReadHostSendData(const int& connectedSocketFileDescriptor) {
    
    const char* sendBuffer;
    std::string message;
    unsigned long sendBufferLength;
    
    while(true) {

        std::cout << "Write a message: ";
        std::getline(std::cin, message);
        sendBuffer = message.c_str();
        sendBufferLength = strlen(sendBuffer);
        SendData(connectedSocketFileDescriptor, sendBuffer, sendBufferLength);
        std::cout << "Sent     -> " << sendBuffer << std::endl;

    }

}

void ReceiveDataWriteHost(const int& connectedSocketFileDescriptor) {

    while(true) {

        char receiveBuffer[1024] = {0};
        unsigned long receiveBufferSize = sizeof(receiveBuffer);
        ReceiveData(connectedSocketFileDescriptor, receiveBuffer, receiveBufferSize);
        std::cout << "Received <- " << receiveBuffer << std::endl;

    }

}

int main() {

    const char* serverIPv4 = "192.168.8.154";
    const unsigned short serverPort = 3651;
    int serverSocket = CreateIPv4TCPSocket();
    sockaddr_in serverSocketAddress = StructIPv4SocketAddress(serverIPv4, serverPort);
    BindAddressToSocket(serverSocket, serverSocketAddress);
    MakeSocketListen(serverSocket);
    std::cout << "Waiting for connection on port " << serverPort << std::endl;
    int connectedSocket = AcceptConnection(serverSocket, serverSocketAddress);
    std::cout << "Connection established.\n";

    std::thread readSendThread (ReadHostSendData, connectedSocket);
    while(true) ReceiveDataWriteHost(connectedSocket);

    close(connectedSocket);
    std::cout << "Connection closed.\n";
    close(serverSocket);
    std::cout << "Server socket closed.\n";
    return 0;

}
