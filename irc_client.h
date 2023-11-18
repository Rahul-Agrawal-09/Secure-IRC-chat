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
    int num=0;
    for(int i=0;i<MAX_CLIENTS;i++){
        if(logged_users[i].user_socket != -1 && strcmp(logged_users[i].username, info->username) != 0){
            vlog_msg("%d-> %s [ID: %d]", ++num, logged_users[i].username, logged_users[i].user_id);
        }
    }
    vlog_msg("Total logged in users: %d", num);
}

void write_all_client(char *input){
    char buffer[MAX_MESSAGE_LEN];
    strncpy(buffer, &input[11], sizeof(buffer)-11);
    vlog_msg("[INFO] Broadcasting message: %s", buffer);
    send(client_socket, input, MAX_MESSAGE_LEN, 0);
}

void create_group_client(char *input){
    send(client_socket, input, MAX_MESSAGE_LEN, 0);
    Group group;
    recv(client_socket, &group, sizeof(Group), 0);
    vlog_msg("[INFO] Group %s created [ID: %d]", group.group_name, group.group_id);
}

void server_pull_request(){
    Message msg;
    recv(client_socket, &msg, sizeof(msg), 0);
    if(strcmp(msg.message_type, "BCAST")==0){
        vlog_msg("[BCAST] %s: %s", msg.username, msg.message);
    }
    if(strcmp(msg.message_type, "WARN")==0){
        vlog_msg("[WARN] %s", msg.message);
    }
    if(strcmp(msg.message_type, "INVITE")==0){
        vlog_msg("[INVITE] %s", msg.message);
    }
    return;
}

void group_invite_client(char *input){
    char buffer[MAX_MESSAGE_LEN];
    strncpy(buffer, &input[14], sizeof(buffer)-11);
    char delim[] = " ";
    char *ptr = strtok(buffer, delim);
    vlog_msg("[INFO] Inviting User: %d in Group: %d", atoi(ptr), atoi(strtok(NULL, " ")));
    send(client_socket, input, MAX_MESSAGE_LEN, 0);
}


void handle_irc_request_client(char* input){
    vlog_msg("[CMD] Entered input: %s", input);

    if(strncmp("/who", input, 4) == 0){
        who_client();
    }
    if(strncmp("/write_all ", input, 11) == 0){
        write_all_client(input);
    }
    if(strncmp(input, "/create_group ", 14) == 0){
        create_group_client(input);
    }
    if(strncmp(input, "/group_invite ", 14) == 0){
        group_invite_client(input);
    }

    // quit the server
    if(strncmp(input, "/quit", 5) == 0){
        quit_server();
    }
}