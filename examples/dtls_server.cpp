#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#define PORT 4444

int main() {
    // 1. Initialization
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = DTLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!SSL_CTX_use_certificate_file(ctx, "yourcert.pem", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "yourkey.pem", SSL_FILETYPE_PEM)) {
        std::cerr << "Error setting up cert and key\n";
        exit(1);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    // 2. Socket setup
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error creating socket: " << strerror(errno) << "\n";
        exit(1);
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Error binding to port: " << strerror(errno) << "\n";
        exit(1);
    }

    std::cout << "Server started. Waiting for connections...\n";

    // 3. DTLS handshake
    // while (1) {
        printf("Waiting for a client...\n");
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        BIO *bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
        if (!bio) {
            std::cerr << "Error creating BIO\n";
            exit(1);
        }
        SSL_set_bio(ssl, bio, bio);

        sockaddr_in client_addr = {};
        socklen_t client_len = sizeof(client_addr);
        char dummy_buf[1];  // Used to detect incoming handshake

        // Wait for an incoming ClientHello from the client
        int len = recvfrom(sockfd, dummy_buf, sizeof(dummy_buf), MSG_PEEK, (struct sockaddr*)&client_addr, &client_len);

        if (len > 0) {
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &client_addr);
        } else {
            std::cerr << "Failed to receive incoming handshake\n";
            exit(1);
        }

        if (SSL_accept(ssl) <= 0) {
            std::cerr << "SSL accept error:\n";
            ERR_print_errors_fp(stderr);  // Existing OpenSSL error print
            
            int sslError = SSL_get_error(ssl, -1);
            std::cerr << "SSL error code: " << sslError << "\n";

            if(errno != 0) {
                std::cerr << "System error: " << strerror(errno) << "\n";
            }
        }

        char buffer[2048];
        int bytes = 0;

        while (true) {
            // Receive data from the client
            bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);

            // If there's an error or the client disconnects
            if (bytes <= 0) {
                break;
            }

            buffer[bytes] = '\0';  // Null-terminate to safely use string functions

            // Echo the data back to the client
            SSL_write(ssl, buffer, bytes);

            // If a newline character is received, break out of the loop
            if (strchr(buffer, '\n')) {
                std::cout << "Newline received. Shutting down server." << std::endl;
                break;
            }
        }

        // Properly shut down the DTLS connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
    // }

    // Cleanup (you should do this in a more organized way with error checking)
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
