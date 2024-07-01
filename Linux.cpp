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

void GetClipboardSendData(const int& connectedSocket) {

    unsigned char* lastClipboardContent = nullptr;
    unsigned char* currentClipboardContent = nullptr;
    const char* sendBuffer;
    unsigned long sendBufferLength;

    while (true) {

        currentClipboardContent = GetClipboardContent();

        if (lastClipboardContent == nullptr || strcmp(reinterpret_cast<const char*>(lastClipboardContent), reinterpret_cast<const char*>(currentClipboardContent)) != 0) {

            unsigned char* encodedClipboard = EncodeBase64(currentClipboardContent);
            sendBuffer = reinterpret_cast<const char*>(encodedClipboard);
            sendBufferLength = strlen(sendBuffer) + 1;

            if ((sendBufferLength - 1 ) != 0) { 

                std::cout << "Sending: decoded - " << strlen(reinterpret_cast<const char*>(currentClipboardContent)) << " | encoded: " << (sendBufferLength-1) <<std::endl;
                SendData(connectedSocket, sendBuffer, sendBufferLength);
                lastClipboardContent = currentClipboardContent;

            } else {
                
                // The clipboard gets seemingly randomly cleared, still looking up the cause, in the meantime this prevents it.
                if (lastClipboardContent != nullptr) SetClipboardContent(lastClipboardContent);
            }

        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

    }

    if (lastClipboardContent != nullptr) delete[] lastClipboardContent;

}

void GetDataSetClipboard(const int& connectedSocket) {

    while (true) {

        char receiveBuffer[87040] = {0};
        unsigned long receiveBufferSize = sizeof(receiveBuffer);
        ReceiveData(connectedSocket, receiveBuffer, receiveBufferSize);

        if (receiveBufferSize > 0) {
            const unsigned char* encodedClipboardContent = reinterpret_cast<const unsigned char*>(receiveBuffer);
            const unsigned char* newClipboardContent = DecodeBase64(encodedClipboardContent);
            if (strlen(reinterpret_cast<const char*>(newClipboardContent)) != 0) {
                std::cout << "Setting clipboard with size: " << strlen(reinterpret_cast<const char *>(newClipboardContent)) << std::endl;
                SetClipboardContent(newClipboardContent);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

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
        char receiveBufferA[87040] = {0};
        unsigned long receiveBufferSize = sizeof(receiveBufferA);
        ReceiveData(connectedSocket, receiveBufferA, receiveBufferSize);
        std::string ok = receiveBufferA;
        if (ok != "OK") throw std::runtime_error("OK not received in Exhange Diffie-Hellman.");
        
        std::cout << "Sending server public...\n";
        const char* serverPublic = diffieHellmanKeys.getPublic();
        unsigned long serverPublicLength = strlen(serverPublic);
        SendData(connectedSocket, serverPublic, serverPublicLength);

        std::cout << "Waiting for clients public...\n";
        char receiveBufferB[87040] = {0};
        ReceiveData(connectedSocket, receiveBufferB, receiveBufferSize);
        const char* clientPublic = receiveBufferB;

        std::cout << "Deriving secret...\n";
        diffieHellmanKeys.generateSecret(clientPublic);

    } else {
        
        std::cout << "Waiting for server prime...\n";
        char receiveBufferA[87040] = {0};
        unsigned long receiveBufferSize = sizeof(receiveBufferA);
        ReceiveData(connectedSocket, receiveBufferA, receiveBufferSize);
        const char* serverPrime = receiveBufferA;

        std::cout << "Sending OK...\n";
        const char* ok = "OK";
        unsigned long okLength = strlen(ok);
        SendData(connectedSocket, ok, okLength);
        
        std::cout << "Waiting for server public...\n";
        char receiveBufferB[87040] = {0};
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
    std::cout << "Deriving AES-256 key from secret...\n";
    diffieHellmanKeys.generateCryptoKey();
    std::cout << "Shared secret and key established\n";

}

int main(int argc, char* argv[]) {

    int xselCheck = system("which xsel > /dev/null 2>&1");
    if (xselCheck != 0) { std::cerr << "Please make sure to have xsel installed on your system.\n"; return 1; }

    if (argc != 4) { std::cerr << "Usage: [client/server] [serverIPv4] [serverPort]\n"; return 1; }

    const std::string executionMode = argv[1];
    const char* serverIPv4 = argv[2];
    const unsigned short serverPort = std::stoi(argv[3]);
    
    std::cout << "Creating socket...\n";
    int socket = CreateIPv4TCPSocket(); 
    sockaddr_in serverSocketAddress = StructIPv4SocketAddress(serverIPv4, serverPort);
    int connectedSocket;

    if (executionMode == "client") {

        std::cout << "Connecting with server...\n";
        connectedSocket = socket;
        ConnectToSocket(connectedSocket, serverSocketAddress);
        
    } else if (executionMode == "server") {

        BindAddressToSocket(socket, serverSocketAddress);
        MakeSocketListen(socket);
        std::cout << "Waiting for client to connect...\n";
        connectedSocket = AcceptConnection(socket, serverSocketAddress);

    } else {

        close(socket);
        std::cerr << "Invalid execution mode. Must either be set to 'client' or 'server'.\n";
        return 1;

    }
    std::cout << "Connection established!\n";

    CheckSocketBufferSize(connectedSocket);

    DiffieHellmanKeys diffieHellmanKeys(128);
    ExchangeDiffieHellman(executionMode, diffieHellmanKeys, connectedSocket);

    ClearClipboard();
    std::thread getDataSetClipboard (GetDataSetClipboard, connectedSocket);
    GetClipboardSendData(connectedSocket);

    return 0;

}
