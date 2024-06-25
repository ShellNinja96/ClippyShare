#include <cstring>
#include <unistd.h>
#include "Networking/LinuxNetworking.h"
#include <iostream>

int main() {
    
    int clientSocket = CreateIPv4TCPSocket();
    const char* serverIPv4 = "192.168.8.154";
    const unsigned short serverPort = 3651;
    sockaddr_in serverSocketAddress = StructIPv4SocketAddress(serverIPv4, serverPort);
    ConnectToSocket(clientSocket, serverSocketAddress);
    std::cout << "Connected to server successfully.\n";

    const char* sendBuffer = "Hello Server";
    unsigned long sendBufferLength = strlen(sendBuffer);
    SendData(clientSocket, sendBuffer, sendBufferLength);
    std::cout << "-> " << sendBuffer << std::endl;

    close(clientSocket);
    std::cout << "Client socket closed.\n";
    return 0;

}
