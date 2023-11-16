#include "crypto.h"

#define KDC_SERVER_IP "127.0.0.1"

User *info; // Store client information including username, password, and ticket
int client_socket;
NsMessage2 msg2; // contains ticket and other info

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
    memset(encrypted_msg2, '\0', BUFFER_SIZE);
    memset((char*)&msg2, '\0', sizeof(NsMessage2));
    int encrypt_data_len = recv(client_socket, encrypted_msg2, BUFFER_SIZE, 0);
    decrypt_data(encrypted_msg2, encrypt_data_len, info->symmetric_key, NULL, (unsigned char*)&msg2);
    printf("Server username: %s\nNonce: %s\nSession key: %s\n", 
    msg2.server_username, msg2.nonce1, msg2.session_key);
    
    // our work with KDC is done
}

// Function to perform chat server authentication
void chat_server_authentication() {
    // Initialize client information including username, password, and ticket
    int nonce2 = generate_nonce();
    MsMessage3 msg3;
    strncpy(msg3.encrypted_ticket, msg2.encrypted_ticket, sizeof(msg2.encrypted_ticket));
    int encrypted_nonce_len = encrypt_data(msg2.session_key, (char*)&nonce2, sizeof(nonce2), NULL, (unsigned char*)&msg3.encrypted_nonce);
    
    
}

// Function to handle the Needham-Schroeder Protocol on the client side
void needham_schroeder_protocol() {
    // Initialize client information including username, password, and ticket
    struct sockaddr_in kdc_addr;
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Error in socket creation");
        exit(1);
    }

    kdc_addr.sin_family = AF_INET;
    kdc_addr.sin_port = htons(KDC_PORT);
    kdc_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Connect to the server
    if (connect(client_socket, (struct sockaddr*)&kdc_addr, sizeof(kdc_addr)) == 0) {
        printf("Connected to KDC\n");
    } else {
        perror("Connection failed");
        exit(1);
    }
    
    kdc_authentication();
    close(client_socket);

    // Connect to the chat server and present the ticket for authentication
    // you can choose when to conncet to chat client

    struct sockaddr_in chat_server_addr;
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Error in socket creation");
        exit(1);
    }

    chat_server_addr.sin_family = AF_INET;
    chat_server_addr.sin_port = htons(CHAT_PORT);
    chat_server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Connect to the server
    if (connect(client_socket, (struct sockaddr*)&chat_server_addr, sizeof(chat_server_addr)) == 0) {
        printf("Connected to KDC\n");
    } else {
        perror("Connection failed");
        exit(1);
    }
    
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
    // printf("My Username: %s\nPassword: %s\nLength of Secret: %ld\n", info->username, info->password ,sizeof(info->symmetric_key));

    // Perform the Needham-Schroeder Protocol
    needham_schroeder_protocol(client_socket);

    // interact with IRC


    return 0;
}
