// REQUIREMENTS
// Windows: OpenSSL
// Linux:   OpenSSL, X11

// COMPILING
// Windows: g++ -o .\clippyshare.exe .\main.cpp .\lib\clipboard.cpp .\lib\networking.cpp .\lib\cryptography.cpp -lcrypto -lws2_32
// Linux:   g++ -o ./clippyshare.bin ./main.cpp ./lib/clipboard.cpp ./lib/networking.cpp ./lib/cryptography.cpp -lcrypto -lX11

// CLEAR REMOVE COMPILE RUN
// Windows: clear; rm .\clippyshare.exe; g++ -o .\clippyshare.exe .\main.cpp .\lib\clipboard.cpp .\lib\networking.cpp .\lib\cryptography.cpp -lcrypto -lws2_32; .\clippyshare.exe client 192.168.8.154 4444 true
// Linux: clear && rm ./clippyshare.bin && g++ -o ./clippyshare.bin ./main.cpp ./lib/clipboard.cpp ./lib/networking.cpp ./lib/cryptography.cpp -lcrypto && ./clippyshare.bin server 192.168.8.154 4444 true
// Linux: while true; do clear; xsel --clipboard --output; sleep 1; done

#include <iostream>
#include <algorithm>
#include <thread>

#include "lib/networking.hpp"
#include "lib/cryptography.hpp"
#include "lib/clipboard.hpp"


std::string rtrim(const std::string& str) {

    std::string result = str;
    result.erase(std::find_if(result.rbegin(), result.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), result.end());
    return result;
}

void getClipboardSendData(Socket& mySocket, DiffieHellman& diffie, Clipboard& clipboard, const bool& verbose) {

    std::string lastClipboard, currentClipboard, encryptedCliboard, encodedClipboard;

    while(true) {

        currentClipboard = clipboard.get();

        if (lastClipboard != currentClipboard) {

            lastClipboard = currentClipboard;

            encryptedCliboard = encryptAES256ECB(currentClipboard, diffie.getAESKey());
            encodedClipboard = encodeBase64(encryptedCliboard);

            if (verbose) std::cout << "-> " << rtrim(currentClipboard) << std::endl;
            mySocket.sendData(encodedClipboard);

        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

    }

}

void getDataSetClipboard(Socket& mySocket, DiffieHellman& diffie, Clipboard& clipboard, const bool& verbose) {

    std::string recvEncoded, recvEncrypted, recvPlain;

    while(true) {

        recvEncoded = mySocket.receiveData();
        recvEncrypted = decodeBase64(recvEncoded);
        recvPlain = decryptAES256ECB(recvEncrypted, diffie.getAESKey());

        if (verbose) std::cout << "<- " << rtrim(recvPlain) << std::endl;
        clipboard.set(recvPlain);

    }

}

int main(int argc, char* argv[]) {

    if (argc != 5) { std::cout << "Usage: executionMode[client/server] serverIPv4[0.0.0.0] serverPort[0-65535] verbose[true/false]\n"; return 1; }

    const std::string executionMode = argv[1];
    const char* serverIPv4 = argv[2];
    const unsigned short serverPort = std::stoi(argv[3]);
    const bool verbose = (std::string(argv[4]) == "true");

    Socket mySocket(executionMode, serverIPv4, serverPort, verbose);
    DiffieHellman diffie(2048);
    Clipboard clipboard;

    if (executionMode == "client") {
        
        if (verbose) std::cout << "Waiting for server's prime number...\n";
        diffie.setPrime(std::string(mySocket.receiveData()).c_str());

        if (verbose) std::cout << "Generating private key...\n";
        diffie.generatePrivate();

        if (verbose) std::cout << "Generating public key...\n";
        diffie.generatePublic();

        if (verbose) std::cout << "Sending public key...\n"; // B
        mySocket.sendData(diffie.getPublic());

        if (verbose) std::cout << "Waiting for server's public key...\n";
        std::string serverPublicKey = mySocket.receiveData();

        if (verbose) std::cout << "Generating shared secret...\n";
        diffie.generateSecret(serverPublicKey.c_str());

    } else {
        
        if (verbose) std::cout << "Generating prime...\n";
        diffie.generatePrime();

        if (verbose) std::cout << "Generating private key...\n";
        diffie.generatePrivate();

        if (verbose) std::cout << "Generating public key...\n";
        diffie.generatePublic();

        if (verbose) std::cout << "Sending prime number...\n";
        mySocket.sendData(diffie.getPrime());

        if (verbose) std::cout << "Waiting for client's public key...\n";
        std::string clientPublicKey = mySocket.receiveData();

        if (verbose) std::cout << "Sending public key...\n";
        mySocket.sendData(diffie.getPublic());

        if (verbose) std::cout << "Generating shared secret...\n";
        diffie.generateSecret(clientPublicKey.c_str());

    }
    if (verbose) std::cout << "Generating AES-256 ECB key...\n";
    diffie.generateAESKey();
    if (verbose) std::cout << "Diffie-Hellman key exchange complete!\n\n";

    clipboard.set("");
    std::thread sendThread(getClipboardSendData, std::ref(mySocket), std::ref(diffie), std::ref(clipboard), std::cref(verbose));
    std::thread recvThread(getDataSetClipboard, std::ref(mySocket), std::ref(diffie), std::ref(clipboard), std::cref(verbose));

    #if defined(__linux__)

        std::thread handlerThread([&](){ clipboard.eventHandler(); });

    #endif

    if (verbose) std::cout << "Clipboard sharing session initialized!\n";

    sendThread.join();
    recvThread.join();

    #if defined(__linux__)

        handlerThread.join();

    #endif

    std::cout << std::endl;
    return 0;

}