# ClippyShare
ClippyShare is a cross-platform C++ utility designed for bidirectional sharing of UTF-8 clipboard content between two hosts over a TCP socket. This tool employs AES-256 ECB mode encryption for security, with keys derived from a 2048-bit Diffie-Hellman key exchange, ensures that encrypted content is transmitted safely over the network with Base64 encoding. Utilizes the OpenSSL library for cryptographic operations.

## Warnings and Security Concerns
Do not use this utility on public networks. The current encryption and key exchange mechanisms do not safeguard against man-in-the-middle (MITM) attacks. Plans to implement certificate-based authentication to enhance security are being considered.

## Dependencies
### Linux:
- X11
- libssl-dev

### Windows:
- openssl

## Compiling Instructions
### Linux:
```
g++ -o ./clippyshare.bin ./main.cpp ./lib/clipboard.cpp ./lib/networking.cpp ./lib/cryptography.cpp -lcrypto -lX11
```
### Windows:
```
g++ -o .\clippyshare.exe .\main.cpp .\lib\clipboard.cpp .\lib\networking.cpp .\lib\cryptography.cpp -lcrypto -lws2_32
```

## Usage
The program operates in either 'client' or 'server' mode. To execute the binary, four arguments must be passed to it in the exact order:

executionMode[client/server] serverIPv4[0.0.0.0] serverPort[0-65535] verbose[true/false]

For example, on a Linux server host, you'd run:
```
./clippyshare.bin server 192.168.1.100 4444 true
```
And on a Windows client host:
```
.\clippyshare.exe client 192.168.1.100 4444 true
```

## Issues
Users are encouraged to report any issues they encounter. Testing is ongoing, and feedback is welcomed.

## Release Notes
### 0.91
- Linux: Mitigated code injection vulnerability by implementing direct interaction with the X server. No longer dependent on xsel.

## License
This utility is Free and Open Source Software, granting users the freedom to use and modify it as they see fit.

