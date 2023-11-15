#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "chat.h"

// #define MAX_SYMMETRIC_KEY_LEN 32 // Length of the derived key (in bytes)
#define SALT_LENGTH 16 // Length of the salt (in bytes)
#define ITERATION_COUNT 10000 // Number of iterations


// Function to perform PBKDF key derivation
void derive_key(char *password, char *key) {
    // Implement key derivation logic using OpenSSL's PBKDF2 function
     // Generate a random salt
    unsigned char salt[SALT_LENGTH];
    if (RAND_bytes(salt, SALT_LENGTH) != 1) {
        fprintf(stderr, "Error generating random salt\n");
        return;
    }

    // Derive the key using PBKDF2
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH, ITERATION_COUNT, EVP_sha256(), MAX_SYMMETRIC_KEY_LEN, key) != 1) {
        fprintf(stderr, "Error deriving key using PBKDF2\n");
        return;
    }

    // printf("Password %s\n", password);
    // for (int i = 0; i < MAX_SYMMETRIC_KEY_LEN; i++) {
    //     printf("%02x", key[i]);
    // }
    // printf("\n");
}


int main() {
    int kdc_socket, chat_socket;
    struct sockaddr_in kdc_addr, chat_addr;
    pthread_t kdc_tid, chat_tid;

    // Initialize OpenSSL library
    OpenSSL_add_all_algorithms();

    // mapping the shared/common data spce
    common_data = (CommonData*)map_common_space();

    // Initialize user data with long-term symmetric keys and tickets
    for (int i = 0; i < MAX_CLIENTS; i++) {
        common_data->users[i].is_online = false;
        strncpy(common_data->users[i].username, "", sizeof(common_data->users[i].username));
        // strncpy(common_data->users[i].ticket, "", sizeof(common_data->users[i].ticket));     // currently not using ticket
        // Generate a password for each user
        strncpy(common_data->users[i].password, generate_username(32), sizeof(common_data->users[i].password));
        // Derive a long-term symmetric key from the user's password
        derive_key(common_data->users[i].password, common_data->users[i].symmetric_key);
    }
    // doing the same for the server
    strncpy(common_data->server.password, generate_username(32), sizeof(common_data->server.password));
    strncpy(common_data->server.username, CHAT_SERVER_USERNAME, sizeof(common_data->server.username));
    derive_key(common_data->server.password, common_data->server.symmetric_key);
    common_data->server.is_online = true;
    common_data->current_user_number = -1;

    // Create a thread for the KDC server
    pthread_create(&kdc_tid, NULL, kdc_thread, NULL);

    // Create a thread for the chat server
    pthread_create(&chat_tid, NULL, chat_thread, NULL);

    // Wait for threads to finish (e.g., using pthread_join)
    pthread_join(kdc_tid, NULL);
    pthread_join(chat_tid, NULL);

    // Clean up OpenSSL resources
    EVP_cleanup();

    return 0;
}
