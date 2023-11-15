#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "kdc.h"

// Function to handle a client connection
void* handle_chat_client(void* arg) {
    // Implement authentication and protocol logic here
    // You should perform Needham-Schroeder authentication here
    // Remember to securely store and handle keys
    // Use a secure communication channel (e.g., TLS/SSL) for key exchange

    int client_socket = *((int*)arg);
    // TODO: Implement authentication and protocol

    // Close the client socket when done
    close(client_socket);
    return NULL;
}

// Function to handle chat server operations
void* chat_thread(void* arg) {
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
    server_addr.sin_port = htons(CHAT_PORT);
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
        pthread_create(&client_thread, NULL, handle_chat_client, &client_socket);
    }

    close(server_socket);
}