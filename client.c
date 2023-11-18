#include "crypto.h"
#include "irc_interface.h"

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
    char encrypted_nonce2[ENCRYPTED_TICKET_LEN];
    char nonce2[MAX_NONCE_LENGTH];
    sprintf(nonce2, "%d", generate_nonce());
    printf("Nonce2: %s\n", nonce2);
    int encrypted_nonce2_len = encrypt_data(msg2.session_key, nonce2, sizeof(nonce2), NULL, encrypted_nonce2);
    
    // send the tickit and encrypted nonce to the chat server
    if(send(client_socket, msg2.encrypted_ticket, msg2.encrypted_ticket_len, 0) == -1)
        perror("Problem sending ticket");
    char ptr[1]; recv(client_socket, ptr, 1, 0);
    if(send(client_socket, encrypted_nonce2, encrypted_nonce2_len, 0) == -1)
        perror("Problem sending encrypted nonce2");

    // getting the challenge from the sever
    Challenge challenge; 
    char encrypted_challenge[BUFFER_SIZE];
    int encrypted_challenge_len = recv(client_socket, encrypted_challenge, BUFFER_SIZE, 0);
    decrypt_data(encrypted_challenge, encrypted_challenge_len, msg2.session_key, NULL, (char*)&challenge);
    printf("Decremented Nonce2: %s\nNonce3: %s\n", challenge.decremented_nonce2, challenge.nonce3);
    if(atoi(challenge.decremented_nonce2) != atoi(nonce2)-1){
        printf("SERVER UnAuthenticated\n");
        perror("Cannot authenticated server");
    }

    // sending response to the challenge from the server
    char response[MAX_NONCE_LENGTH];
    sprintf(response, "%d", atoi(challenge.nonce3)-1);
    char encrypted_reponse[BUFFER_SIZE];
    size_t encrypted_response_len = encrypt_data(msg2.session_key, response, sizeof(response), NULL, encrypted_reponse);
    if(send(client_socket, encrypted_reponse, encrypted_response_len, 0) == -1)
        perror("Error sending challenge");    

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
    printf("PRESS ENTER TO CONNECT TO CHAT SERVER: ");
    getchar();

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
        printf("Connected to CHAT server\n");
    } else {
        perror("Connection failed");
        exit(1);
    }
    
    chat_server_authentication();

    // Close the client socket when done
    close(client_socket);
}

// launch the irc_interfaace
void launch_irc_interface(){
    // initialize ncurses
    initscr();
    cbreak();
    // noecho();

    // Create a new thread and pass it the argument
    pthread_t thread_id;
    int result = pthread_create(&thread_id, NULL, init__irc_interface, info->username);
    if (result != 0) {
        perror("Error creating thread");
        return;
    }

    // Wait for the thread to finish
    result = pthread_join(thread_id, NULL);
    if (result != 0) {
        perror("Error joining thread");
        return;
    }
    endwin();
    return;
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

    // Launch the IRC interface
    launch_irc_interface();


    return 0;
}
