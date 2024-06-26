#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <thread>
#include "Networking/LinuxNetworking.h"
#include "ClipboardUtils/LinuxClipboard.h"

void GetClipboardSendData(const int& socketFileDescriptor) {
    
    std::string lastClipboardContent;
    std::string currentClipboardContent;
    const char* sendBuffer;
    unsigned long sendBufferLength;

    while(true) {

        currentClipboardContent = GetClipboardContent();
        if (lastClipboardContent != currentClipboardContent) {
            sendBuffer = currentClipboardContent.c_str();
            sendBufferLength = strlen(sendBuffer);
            SendData(socketFileDescriptor, sendBuffer, sendBufferLength);
            lastClipboardContent = currentClipboardContent;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

    }

}

void GetDataSetClipboard(const int& socketFileDescriptor) {

    while(true) {
        char receiveBuffer[4096] = {0};
        unsigned long receiveBufferSize = sizeof(receiveBuffer);
        ReceiveData(socketFileDescriptor, receiveBuffer, receiveBufferSize);
        std::string receiveBufferString = receiveBuffer;
        SetClipboardContent(receiveBufferString);
    }

}

int main(int argc, char* argv[]) {

    int xselCheck = system("which xsel > /dev/null 2>&1");
    if (xselCheck != 0) { std::cerr << "Please make sure to have xsel installed on your system.\n"; return 1; }

    if (argc != 4) { std::cerr << "Usage: [client/server] [serverIPv4] [serverPort]\n"; return 1; }

    const std::string executionMode = argv[1];
    const char* serverIPv4 = argv[2];
    const unsigned short serverPort = std::stoi(argv[3]);
    
    int socket = CreateIPv4TCPSocket(); 
    sockaddr_in serverSocketAddress = StructIPv4SocketAddress(serverIPv4, serverPort);
    int connectedSocket;

    if (executionMode == "client") {

        connectedSocket = socket;
        ConnectToSocket(connectedSocket, serverSocketAddress);
        
    } else if (executionMode == "server") {

        BindAddressToSocket(socket, serverSocketAddress);
        MakeSocketListen(socket);
        connectedSocket = AcceptConnection(socket, serverSocketAddress);

    } else {

        close(socket);
        std::cerr << "Invalid execution mode. Must either be set to 'client' or 'server'.\n";
        return 1;

    }
    std::cout << "Connection established\n";

    std::thread getDataSetClipboard (GetDataSetClipboard, connectedSocket);
    GetClipboardSendData(connectedSocket);

    return 0;

}
