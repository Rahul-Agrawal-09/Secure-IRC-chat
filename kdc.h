#include "crypto.h"

LoginProtection login_protection[MAX_CLIENTS];

// Function to handle a client connection
void* handle_kdc_client(void* arg) {
    int client_socket = *((int*)arg);

    //receove message1 from client
    NsMessage1 msg1;
    recv(client_socket, &msg1, sizeof(NsMessage1), 0);
    printf("\nMessage1 from client\nClient: %s\nServer: %s\nNonce: %s\n", msg1.client_username, msg1.server_username, msg1.nonce1);


    // using aes256 to encrypt the tickit and other informations 
    NsMessage2 msg2;
    memset((char*)&msg2, '\0', sizeof(NsMessage2));
    strncpy(msg2.nonce1, msg1.nonce1, sizeof(msg2.nonce1));
    strncpy(msg2.server_username, CHAT_SERVER_USERNAME, sizeof(msg2.server_username));
    
    // finding the user in the database
    User *current_user = NULL;
    LoginProtection *current_login_protection;
    for(int i=0;i<MAX_CLIENTS;i++){
        if(strcmp(msg1.client_username, common_data->users[i].username) == 0){
            current_user = &common_data->users[i];
            current_login_protection = &common_data->login_protection[i];
        }
    }
    if(current_user == NULL){
        perror("Requested User Does Not Exist");
        exit(EXIT_SUCCESS);
    }
    // counting the login attempt
    if(current_login_protection->password_attemps>=MAX_PASSWORD_ATTEMPTS){
        current_login_protection->blocked = true;
        printf("[ALERT] User %s is BLOCKED due to Maximum number of Attemps.\n", current_user->username);
        printf("Restart server to unblock it\n");
        pthread_exit(0);
    }
    else{
        current_login_protection->password_attemps ++;
    }

    // Making a random session key
    char session_key[MAX_SESSION_KEY_LEN];//"ThisIsSessionKeyThisIsSessionKey";
    strncpy(session_key, generate_username(32), sizeof(session_key));
    strncpy(msg2.session_key, session_key, sizeof(msg2.session_key));
    
    // generating ticket
    Ticket ticket;
    strncpy(ticket.requesting_username, current_user->username, sizeof(ticket.requesting_username));
    strncpy(ticket.session_key, session_key, sizeof(ticket.session_key));
    msg2.encrypted_ticket_len = encrypt_data(common_data->server.symmetric_key, (unsigned char*)&ticket, sizeof(Ticket), NULL, msg2.encrypted_ticket);
    printf("ETickit lenth %ld\n", msg2.encrypted_ticket_len);

    Ticket ticket2;
    decrypt_data(msg2.encrypted_ticket, msg2.encrypted_ticket_len, common_data->server.symmetric_key, NULL, (unsigned char *)&ticket2);
    printf("Session key: %s\n", ticket2.session_key);

    // encrypting and sending the message
    unsigned char encrypted_msg2[BUFFER_SIZE]; // buffer can be small check
    int encrypt_data_len = encrypt_data(current_user->symmetric_key, (unsigned char*)&msg2, sizeof(msg2), NULL, (unsigned char*)encrypted_msg2);
    send(client_socket, encrypted_msg2, encrypt_data_len, 0);
    // work of KDC completed here

    // Close the client socket 
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

