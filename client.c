#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common.h"

#define KDC_SERVER_IP "127.0.0.1"
#define KDC_PORT 12345
#define CHAT_PORT 54321

User *info; // Store client information including username, password, and ticket
int client_socket;

// Function to perform KDC authentication
void kdc_authentication() {
    
    // sending the A, B, Nonce1 to KDC
    NsMessage1 msg1;
    strncpy(msg1.client_username, info->username, sizeof(msg1.client_username));
    strncpy(msg1.server_username, common_data->server.username, sizeof(msg1.client_username));
    sprintf(msg1.nonce1, "%d", generate_nonce());
    send(client_socket, &msg1, sizeof(NsMessage1), 0);

    // receive response from KDC



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

    common_data = (CommonData*)map_common_space();
    int my_index = -1;
    // Initializing myinformaiton
    char *username = getenv("LOGNAME");
    if (username == NULL) {
        perror("Error getting username");
        return 1;
    }

    // Comparing Not working
    // for(int i=0;i<MAX_CLIENTS;i++){
    //     printf("%s\n", common_data->users[i].username);
    //     if(strncmp(common_data->users[i].username, username, strlen(common_data->users[i].username))){
    //         my_index = i;
    //         break;
    //     }
    // }
    if(my_index==-1){
        common_data->current_user_number += 1;
        my_index = common_data->current_user_number;
    }
    if(common_data->current_user_number>=MAX_CLIENTS){
        perror("Client Threashold reached");
        return 1;
    }
    printf("My Index: %d\n", my_index);
    info = &common_data->users[my_index];
    strncpy(info->username, username, sizeof(info->username));
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
