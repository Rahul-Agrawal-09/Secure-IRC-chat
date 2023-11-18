#include "irc_interface.h"

User *info; // Store client information including username, password, and ticket
int client_socket;
NsMessage2 msg2; // contains ticket and other info

void quit_server(){
    char request[] = "/quit";
    send(client_socket, request, sizeof(request), 0);
}

void who_client(){
    log_msg("LOGGED IN USERS ARE:");
    char request[] = "/who";
    send(client_socket, request, sizeof(request), 0);
    LoggedUser logged_users[MAX_CLIENTS];
    recv(client_socket, logged_users, sizeof(logged_users), 0);
    int num=1;
    for(int i=0;i<MAX_CLIENTS;i++){
        if(logged_users[i].user_socket != -1){
            vlog_msg("%d-> %s", num++, logged_users[i].username);
        }
    }
}

void write_all_clien(){

}

void create_group_client(){

}


void handle_irc_request_client(char* input){
    vlog_msg("Entered input: %s", input);
    if(strncmp("/who", input, 4) == 0)
        who_client();
    
    // close the client
    if(strncmp(input, "/quit", 5) == 0)
        quit_server();
}