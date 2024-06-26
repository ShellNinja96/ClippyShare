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
g++ -o Linux Linux.cpp ./Networking/LinuxNetworking.cpp ./ClipboardUtils/LinuxClipboard.cpp
```
### Windows:
- To be implemented...

## Future commits
- Linux: Some form of encryption;
- Windows: Client-server communication (Create, Bind, Accept, Connect, Send and Receive functions)
- Windows: Clipboard utilities (Getters and setters for the clipboard)
- Windows: Some for of encryption;
