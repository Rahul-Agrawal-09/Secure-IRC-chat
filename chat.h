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

    int client_socket = *((int*)arg);
    
    // getting the tickit and encrypted nonce2
    unsigned char encrypted_ticket[BUFFER_SIZE];
    char encrypted_nonce2[ENCRYPTED_TICKET_LEN];
    size_t encrypted_ticket_len = recv(client_socket, encrypted_ticket, BUFFER_SIZE, 0);
    send(client_socket, " ", 1, 0);
    int encrypted_nonce_len = recv(client_socket, encrypted_nonce2, ENCRYPTED_TICKET_LEN, 0);
    // Decrypting the tickit and the nonce
    Ticket ticket;
    char nonce2[MAX_NONCE_LENGTH];
    decrypt_data(encrypted_ticket, encrypted_ticket_len, common_data->server.symmetric_key, NULL, (unsigned char *)&ticket);
    decrypt_data(encrypted_nonce2, encrypted_nonce_len, ticket.session_key, NULL, nonce2);
    printf("Requesting User: %s\nSession key: %s\nNonce2: %s\n",ticket.requesting_username, ticket.session_key, nonce2);


    // constructing and sending challenge to the client
    Challenge challenge;
    sprintf(challenge.decremented_nonce2, "%d", atoi(nonce2)-1);
    sprintf(challenge.nonce3, "%d", generate_nonce());
    printf("Nonce3: %s\n", challenge.nonce3);
    char encrypted_challenge[BUFFER_SIZE];
    size_t encrypted_challenge_len = encrypt_data(ticket.session_key, (char*)&challenge, sizeof(Challenge), NULL, encrypted_challenge);
    if(send(client_socket, encrypted_challenge, encrypted_challenge_len, 0) == -1)
        perror("Error sending challenge");

    // receiving the response to the challenge
    char response[MAX_NONCE_LENGTH]; 
    char encrypted_reponse[BUFFER_SIZE];
    int encrypted_response_len = recv(client_socket, encrypted_reponse, BUFFER_SIZE, 0);
    decrypt_data(encrypted_reponse, encrypted_response_len, ticket.session_key, NULL, response);
    if(atoi(response) != atoi(challenge.nonce3)-1){
        printf("CLIENT UnAuthenticated");
        perror("Cannot authenticated client");
    }

    printf("Sucessfully Authenticated Client %s\n", ticket.requesting_username);
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