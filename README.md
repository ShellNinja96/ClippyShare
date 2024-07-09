# ClippyShare 0.9
A bidirectional UTF-8 clipboard content sharing utility written in C++. Shares clipboard content between two hosts (a client and a server) over a TCP socket. All clipboard content sent over the socket is encrypted using AES-256 ECB mode encryption and encoded in Base64. The AES-256 keys are derived from a Diffie-Hellman key exchange (2048 bit). All cryptographic operations are performed with the OpenSSL library. Prime generation (server-side) might be a bit slow depending on your turing machine, but once it's done, remaining operations should be swift.

## Dependencies
### Linux:
- xsel 1.2.1
- libssl-dev

### Windows:
- openssl

## Compiling
### Linux:
```
g++ -o ./clippyshare.bin ./main.cpp ./lib/clipboard.cpp ./lib/networking.cpp ./lib/cryptography.cpp -lcrypto
```
### Windows:
```
g++ -o .\clippyshare.exe .\main.cpp .\lib\clipboard.cpp .\lib\networking.cpp .\lib\cryptography.cpp -lcrypto -lws2_32
```

## Usage
The program can be executed in either 'client' or 'server' mode. To execute the binary, four arguments must be passed to it in the exact order:
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
Feel free to submit any issues you encounter while using this program. Testing is in progress.

## License
Free and Open Source Software. Do whatever you'd like with it <3