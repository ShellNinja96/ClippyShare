#ifndef LINUX_NETWORKING_H
#define LINUX_NETWORKING_H

#include <netinet/in.h>

int CreateIPv4TCPSocket();
sockaddr_in StructIPv4SocketAddress(const char* serverIPv4, const unsigned short& port);
void BindAddressToSocket(const int& socketFileDescriptor, const sockaddr_in& socketAddress);
void MakeSocketListen(const int& socketFileDescriptor);
int AcceptConnection(const int& serverSocket, sockaddr_in& serverSocketAddress);
void ConnectToSocket(const int& socketFileDescriptor, const sockaddr_in& serverAddress);



#endif //LINUX_NETWORKING_H
