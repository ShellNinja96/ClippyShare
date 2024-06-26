#include <cstring>
#include <unistd.h>
#include "Networking/LinuxNetworking.h"
#include <iostream>
#include <thread>

void ReadHostSendData(const int& clientSocketFileDescriptor) {
    
    const char* sendBuffer;
    std::string message;
    unsigned long sendBufferLength;
    
    while(true) {

        std::cout << "Write a message: ";
        std::getline(std::cin, message);
        sendBuffer = message.c_str();
        sendBufferLength = strlen(sendBuffer);
        SendData(clientSocketFileDescriptor, sendBuffer, sendBufferLength);
        std::cout << "Sent     -> " << sendBuffer << std::endl;

    }

}

void ReceiveDataWriteHost(const int& clientSocketFileDescriptor) {

    while(true) {

        char receiveBuffer[1024] = {0};
        unsigned long receiveBufferSize = sizeof(receiveBuffer);
        ReceiveData(clientSocketFileDescriptor, receiveBuffer, receiveBufferSize);
        std::cout << "Received <- " << receiveBuffer << std::endl;

    }

}

int main() {
    
    int clientSocket = CreateIPv4TCPSocket();
    const char* serverIPv4 = "192.168.8.154";
    const unsigned short serverPort = 3651;
    sockaddr_in serverSocketAddress = StructIPv4SocketAddress(serverIPv4, serverPort);
    ConnectToSocket(clientSocket, serverSocketAddress);
    std::cout << "Connected to server successfully.\n";

    std::thread readSendThread (ReadHostSendData, clientSocket);
    while(true) ReceiveDataWriteHost(clientSocket);

    close(clientSocket);
    std::cout << "Client socket closed.\n";
    return 0;

}
