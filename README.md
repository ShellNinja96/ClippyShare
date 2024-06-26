# ClippyShare
This program is intended to share UTF-8 clipboard content between 2 hosts on the same LAN (a client and a server).

## About the project
The goal of the project is to be able to share clipboard content between Linux (x11) and Windows hosts.
The program checks in the hosts in which it is running, if any modification to the clipboard has ocurred, if so, then the content of the clipboard is sent over a TCP socket to the other host.
So far only Linux clipboard sharing as been implemented.

## WARNING
Encryption wasn't implemented yet, any content shared over the network is in plain text.

## Compiling
### Linux:
```
g++ -o ClippyShare Linux.cpp ./Networking/LinuxNetworking.cpp ./ClipboardUtils/LinuxClipboard.cpp
```
### Windows:
- To be implemented...

## Usage
The program can be executed either in 'client' or 'server' mode. To execute the binary 3 arguments must be passed to it in exact order:
./BinaryFileName [client/server] [serverIPv4] [serverPort]

For example in the server host you'd run:
```
ClippyShare server 192.168.1.1 4444
```
And in the client host:
```
ClippyShare.exe client 192.168.1.1 4444
```

## Future commits
- Linux: Some form of encryption;
- Windows: Client-server communication (Create, Bind, Accept, Connect, Send and Receive functions)
- Windows: Clipboard utilities (Getters and setters for the clipboard)
- Windows: Some form of encryption;
