#include <unistd.h>
#include "Networking/LinuxNetworking.h"
#include <iostream>

int main() {

    const char* serverIPv4 = "192.168.8.154";
    const unsigned short serverPort = 3651;
    int serverSocket = CreateIPv4TCPSocket();
    sockaddr_in serverSocketAddress = StructIPv4SocketAddress(serverIPv4, serverPort);
    BindAddressToSocket(serverSocket, serverSocketAddress);
    MakeSocketListen(serverSocket);
    std::cout << "Waiting for connection on port " << serverPort << std::endl;
    int clientSocket = AcceptConnection(serverSocket, serverSocketAddress);
    std::cout << "Connection established.\n";
    close(clientSocket);
    std::cout << "Connection closed.\n";
    close(serverSocket);
    std::cout << "Server socket closed.\n";
    return 0;

}
