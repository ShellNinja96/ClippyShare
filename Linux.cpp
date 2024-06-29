#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <unistd.h>
#include <iostream>
#include <thread>
#include "CryptographyUtils/CryptographyUtils.h"
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

void ExchangeDiffieHellman(const std::string& executionMode, DiffieHellmanKeys& diffieHellmanKeys, const int& connectedSocket) {

    if (executionMode == "server") {
        
        std::cout << "Generating server prime...\n";
        diffieHellmanKeys.generatePrime();

        std::cout << "Generating server private...\n";
        diffieHellmanKeys.generatePrivate();

        std::cout << "Generating server public...\n";
        diffieHellmanKeys.generatePublic();


        std::cout << "Sending server prime...\n";
        const char* serverPrime = diffieHellmanKeys.getPrime();
        unsigned long serverPrimeLength = strlen(serverPrime);
        SendData(connectedSocket, serverPrime, serverPrimeLength);

        std::cout << "Waiting for OK...\n";
        char receiveBufferA[4096] = {0};
        unsigned long receiveBufferSize = sizeof(receiveBufferA);
        ReceiveData(connectedSocket, receiveBufferA, receiveBufferSize);
        std::string ok = receiveBufferA;
        if (ok != "OK") throw std::runtime_error("OK not received in Exhange Diffie-Hellman.");
        
        std::cout << "Sending server public...\n";
        const char* serverPublic = diffieHellmanKeys.getPublic();
        unsigned long serverPublicLength = strlen(serverPublic);
        SendData(connectedSocket, serverPublic, serverPublicLength);

        std::cout << "Waiting for clients public...\n";
        char receiveBufferB[4096] = {0};
        ReceiveData(connectedSocket, receiveBufferB, receiveBufferSize);
        const char* clientPublic = receiveBufferB;

        std::cout << "Deriving secret...\n";
        diffieHellmanKeys.generateSecret(clientPublic);

    } else {
        
        std::cout << "Waiting for server prime...\n";
        char receiveBufferA[4096] = {0};
        unsigned long receiveBufferSize = sizeof(receiveBufferA);
        ReceiveData(connectedSocket, receiveBufferA, receiveBufferSize);
        const char* serverPrime = receiveBufferA;

        std::cout << "Sending OK...\n";
        const char* ok = "OK";
        unsigned long okLength = strlen(ok);
        SendData(connectedSocket, ok, okLength);
        
        std::cout << "Waiting for server public...\n";
        char receiveBufferB[4096] = {0};
        ReceiveData(connectedSocket, receiveBufferB, receiveBufferSize);
        const char* serverPublic = receiveBufferB;
        
        std::cout << "Setting client prime...\n";
        diffieHellmanKeys.setPrime(serverPrime);

        std::cout << "Generating client private...\n";
        diffieHellmanKeys.generatePrivate();

        std::cout << "Generating client public...\n";
        diffieHellmanKeys.generatePublic();

        std::cout << "Sending client public...\n";
        const char* clientPublic = diffieHellmanKeys.getPublic();
        unsigned long clientPublicLength = strlen(clientPublic);
        SendData(connectedSocket, clientPublic, clientPublicLength);

        std::cout << "Deriving secret...\n";
        diffieHellmanKeys.generateSecret(serverPublic);

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

    DiffieHellmanKeys diffieHellmanKeys(2048);
    ExchangeDiffieHellman(executionMode, diffieHellmanKeys, connectedSocket);
    std::cout << "Derived shared secret\n";

    std::thread getDataSetClipboard (GetDataSetClipboard, connectedSocket);
    GetClipboardSendData(connectedSocket);

    return 0;

}
