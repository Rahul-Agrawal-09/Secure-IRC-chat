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

#define KDC_SERVER_IP "127.0.0.1"

User *info; // Store client information including username, password, and ticket
int client_socket;

int decrypt_data(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                 unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Initialize the decryption operation
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Provide the message to be decrypted, and obtain the plaintext output
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len = len;

    // Finalize the decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    printf("Length %d\n", plaintext_len);
    return plaintext_len;
}

// Function to perform KDC authentication
void kdc_authentication() {
    
    // sending the A, B, Nonce1 to KDC
    NsMessage1 msg1;
    strncpy(msg1.client_username, info->username, sizeof(msg1.client_username));
    strncpy(msg1.server_username, CHAT_SERVER_USERNAME, sizeof(msg1.client_username));
    sprintf(msg1.nonce1, "%d", generate_nonce());
    send(client_socket, &msg1, sizeof(NsMessage1), 0);

    // receive response from KDC
    unsigned char encrypted_msg2[BUFFER_SIZE];
    NsMessage2 msg2;
    memset(encrypted_msg2, '\0', BUFFER_SIZE);
    memset((char*)&msg2, '\0', sizeof(NsMessage2));
    int encrypt_data_len = recv(client_socket, encrypted_msg2, BUFFER_SIZE, 0);
    decrypt_data(encrypted_msg2, encrypt_data_len, info->symmetric_key, NULL, (unsigned char*)&msg2);
    printf("Server username: %s\nNonce: %s\nEncrypted ticeket: %s\nSession key: %s\n", 
    msg2.server_username, msg2.nonce1, msg2.encrypted_ticket, msg2.session_key);




}

// Function to perform chat server authentication
void chat_server_authentication() {
    // Implement chat server authentication logic here
}

// Function to handle the Needham-Schroeder Protocol on the client side
void needham_schroeder_protocol(int client_socket) {
    // Implement Needham-Schroeder Protocol logic here
    // You should securely exchange keys and authenticate with the server
    // Use a secure communication channel (e.g., TLS/SSL) for key exchange

    // TODO: Implement the Needham-Schroeder Protocol
    // Connect to the KDC server to obtain a ticket
    kdc_authentication();

    // Connect to the chat server and present the ticket for authentication
    chat_server_authentication();

    // Close the client socket when done
    close(client_socket);
}

int main() {

    // Initializing myinformaiton
    info = (User*)malloc(sizeof(User));
    char *username = getenv("LOGNAME");
    if (username == NULL) {
        perror("Error getting username");
        return 1;
    }
    printf("Enter your Password: ");
    scanf("%s", info->password); // password
    strncpy(info->username, username, sizeof(info->username)); // username
    derive_key(info->password, info->symmetric_key);
    info->is_online = true;
    printf("My Username: %s\nPassword: %s\nLength of Secret: %ld\n", info->username, info->password ,sizeof(info->symmetric_key));

    // Initialize client information including username, password, and ticket
    struct sockaddr_in server_addr;

    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Error in socket creation");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(KDC_PORT);
    server_addr.sin_addr.s_addr = inet_addr(KDC_SERVER_IP);

    // Connect to the server
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
        printf("Connected to KDC\n");
    } else {
        perror("Connection failed");
        exit(1);
    }

    // Perform the Needham-Schroeder Protocol
    needham_schroeder_protocol(client_socket);

    return 0;
}
