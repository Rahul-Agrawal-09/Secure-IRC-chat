#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include "common.h"

void encrypt_data(char*aes_key, const char* plaintext, int plaintext_length, unsigned char* ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int encrypted_length;

    // Initialize the encryption context
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, NULL);

    // Encrypt the data
    EVP_EncryptUpdate(ctx, ciphertext, &encrypted_length, (const unsigned char*)plaintext, plaintext_length);
    EVP_EncryptFinal_ex(ctx, ciphertext + encrypted_length, &encrypted_length);

    // Close the encryption context
    EVP_CIPHER_CTX_free(ctx);
}

// Function to handle a client connection
void* handle_kdc_client(void* arg) {
    // Implement authentication and protocol logic here
    // You should perform Needham-Schroeder authentication here
    // Remember to securely store and handle keys
    // Use a secure communication channel (e.g., TLS/SSL) for key exchange

    int client_socket = *((int*)arg);

    //receove message1 from client
    NsMessage1 msg1;
    recv(client_socket, &msg1, sizeof(NsMessage1), 0);
    printf("Message1 from client:\nClient: %s\nServer: %s\nNonce: %s\n", msg1.client_username, msg1.server_username, msg1.nonce1);

    // using aes256 to encrypt the tickit and other informations 
    // char plan_text[BUFFER_SIZE];
    // sprintf(plan_text, "%d", num);
    // char ticket[BUFFER_SIZE];
    // encrypt_data(common_data->server.symmetric_key, );

    // Close the client socket when done
    close(client_socket);
    return NULL;
}

// Function to handle KDC authentication
void* kdc_thread(void* arg) {
    int server_socket;
    struct sockaddr_in server_addr;
    socklen_t addr_size = sizeof(server_addr);

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error in socket creation");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(KDC_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, addr_size) < 0) {
        perror("Error in binding");
        exit(1);
    }

    // Listen for incoming connections
    if (listen(server_socket, MAX_CLIENTS) == 0) {
        printf("Listening on CHAT port...\n");
    } else {
        printf("Error in listening\n");
    }

    while (1) {
        // Accept client connections
        int client_socket = accept(server_socket, (struct sockaddr*)&server_addr, &addr_size);
        if (client_socket < 0) {
            perror("Error in accepting");
            continue;
        }

        // Create a new thread to handle the client
        pthread_t client_thread;
        pthread_create(&client_thread, NULL, handle_kdc_client, &client_socket);
    }

    close(server_socket);
}

