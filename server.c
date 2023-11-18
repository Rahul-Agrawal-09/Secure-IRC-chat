#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "chat.h"

// #define MAX_SYMMETRIC_KEY_LEN 32 // Length of the derived key (in bytes)

int main() {
    int kdc_socket, chat_socket;
    struct sockaddr_in kdc_addr, chat_addr;
    pthread_t kdc_tid, chat_tid;

    // Initialize OpenSSL library
    OpenSSL_add_all_algorithms();

    // mapping the shared/common data spce
    common_data = (CommonData*)malloc(sizeof(CommonData));
    char usernames[MAX_CLIENTS][MAX_USERNAME_LEN] = {
        "rahul", "mark", "bill", "larry", "raju", "shyam", "alice", "bob",  "charli", "root"
    };
    char passwords[MAX_CLIENTS][MAX_PASSWORD_LEN] = {
        "rahul", "mark", "bill", "larry", "raju", "shyam", "alice", "bob",  "charli", "root"
    };

    // Initialize user data with long-term symmetric keys and tickets
    for (int i = 0; i < MAX_CLIENTS; i++) {
        strncpy(common_data->users[i].username, usernames[i], sizeof(common_data->users[i].username));
        // strncpy(common_data->users[i].ticket, "", sizeof(common_data->users[i].ticket));     // currently not using ticket
        // Generate a password for each user
        strncpy(common_data->users[i].password, passwords[i], sizeof(common_data->users[i].password));
        // Derive a long-term symmetric key from the user's password
        derive_key(common_data->users[i].password, common_data->users[i].symmetric_key);
        logged_users[i].user_socket = -1;
    }
    // doing the same for the server
    strncpy(common_data->server.password, generate_username(32), sizeof(common_data->server.password));
    strncpy(common_data->server.username, CHAT_SERVER_USERNAME, sizeof(common_data->server.username));
    derive_key(common_data->server.password, common_data->server.symmetric_key);

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
