#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include "common.h"

int encrypt_data(char*aes_key, const char* plaintext, int plaintext_length, char* iv ,unsigned char* ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Initialise the encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;

    // Finalise the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
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
    printf("\nMessage1 from client\nClient: %s\nServer: %s\nNonce: %s\n", msg1.client_username, msg1.server_username, msg1.nonce1);

    // using aes256 to encrypt the tickit and other informations 
    NsMessage2 msg2;
    // strncpy(msg2.nonce1, msg1.nonce1, sizeof(msg2.nonce1));
    // strncpy(msg2.server_username, CHAT_SERVER_USERNAME, sizeof(msg2.server_username));
    // // TODO change session key and encrypted ticket
    // strncpy(msg2.session_key, generate_username(SESSION_KEY_LEN), sizeof(msg2.session_key));
    // strncpy(msg2.encrypted_ticket, "ThisIsTIcket", sizeof(msg2.encrypted_ticket));

    memset((char*)&msg2, '\0', sizeof(NsMessage2));
    strcpy(msg2.nonce1, msg1.nonce1);
    strcpy(msg2.server_username, CHAT_SERVER_USERNAME);
    // TODO change session key and encrypted ticket
    strcpy(msg2.session_key, "This is Session Key\0");
    strcpy(msg2.encrypted_ticket, "ThisIsTIcket\0");
    
    User *current_user = NULL;
    for(int i=0;i<MAX_CLIENTS;i++){
        if(strcmp(msg1.client_username, common_data->users[i].username) == 0)
            current_user = &common_data->users[i];
    }
    if(current_user == NULL){
        perror("Requested User Does Not Exist");
        exit(EXIT_SUCCESS);
    }
    unsigned char encrypted_msg2[BUFFER_SIZE]; // buffer can be small check
    memset(encrypted_msg2, '\0', BUFFER_SIZE);
    int encrypt_data_len = encrypt_data(current_user->symmetric_key, (unsigned char*)&msg2, sizeof(msg2), NULL, (unsigned char*)encrypted_msg2);
    send(client_socket, encrypted_msg2, encrypt_data_len, 0);
    



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
        printf("Listening on KDC port...\n");
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

