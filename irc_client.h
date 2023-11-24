#include "irc_interface.h"

User *info; // Store client information including username, password, and ticket
int client_socket;
int pending_group_invitations[MAX_GROUPS];
int joined_group[MAX_GROUPS];
int pending_public_key_request[MAX_CLIENTS];
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
        for(int i=0;i<MAX_GROUPS;i++){
            if(pending_group_invitations[i]<0){
                pending_group_invitations[i] = msg.group_id;
                break;
            }
        }
        vlog_msg("[INVITE] %s", msg.message);
    }
    if(strcmp(msg.message_type, "INFO")==0){
        vlog_msg("[INFO] %s", msg.message);
    }
    if(strcmp(msg.message_type, "DIFI")==0){
        vlog_msg("[ALERT] %s", msg.message);
        vlog_msg("[INFO] Public requested by user %s for Diffie-Hellman Key Exchange", msg.username);
        log_msg("[INFO] Sending Public Key....");
    }
    if(strcmp(msg.message_type, "PUB_REQUEST")==0){
        for(int i=0;i<MAX_CLIENTS;i++){
            if(pending_public_key_request[i] < 0){
                pending_public_key_request[i] = msg.group_id;
                break;
            }
        }
        vlog_msg("[ALERT] %s", msg.message);
    }
    if(strcmp(msg.message_type, "PUB_RESPONSE")==0){
        vlog_msg("[INFO] %s", msg.message);
    }
    if(strcmp(msg.message_type, "GCAST")==0){
        vlog_msg("[Group:%d] [User:%s] %s", msg.group_id, msg.username, msg.message);
    }
    return;
}

void group_invite_client(char *input){
    char buffer[MAX_MESSAGE_LEN];
    strncpy(buffer, &input[14], sizeof(buffer)-14);
    char delim[] = " ";
    char *ptr = strtok(buffer, delim);
    vlog_msg("[INFO] Inviting User: %d in Group: %d", atoi(ptr), atoi(strtok(NULL, " ")));
    send(client_socket, input, MAX_MESSAGE_LEN, 0);
}

void group_invite_accept_client(char *input){
    char buffer[MAX_MESSAGE_LEN];
    strncpy(buffer, &input[21], sizeof(buffer)-21);
    char delim[] = " ";
    char *ptr = strtok(buffer, delim);
    int group_id = atoi(ptr);
    bool found = false;
    for(int i=0;i<MAX_GROUPS;i++){
        if(pending_group_invitations[i] == group_id){
            found = true;
            pending_group_invitations[i] = -1;
            break;
        }
    }
    if(found){
        vlog_msg("[INFO] Accepting Inviting of Group: %d", group_id);
        send(client_socket, input, MAX_MESSAGE_LEN, 0);
    }
    else{
        vlog_msg("[WARN] Group Invitation NOT found Group ID: %d", group_id);
    }
}

void init_group_dhxchg_client(char *input){
    send(client_socket, input, MAX_MESSAGE_LEN, 0);
    DhPublicKeys public_keys [MAX_CLIENTS];
    recv(client_socket, public_keys, sizeof(public_keys), 0);
    log_msg("[INFO] Receiving all public keys");
    compute_group_key(public_keys, info);
}

void request_public_key_client(char *input){
    char buffer[MAX_MESSAGE_LEN];
    send(client_socket, input, MAX_MESSAGE_LEN, 0);
    strncpy(buffer, &input[20], sizeof(buffer)-20);
    char delim[] = " ";
    char *ptr = strtok(buffer, delim);
    vlog_msg("[INFO] Requesting Public Key of user: %d", atoi(ptr));
}

void send_public_key_client(char *input){
    char buffer[MAX_MESSAGE_LEN];
    send(client_socket, input, MAX_MESSAGE_LEN, 0);
    strncpy(buffer, &input[17], sizeof(buffer)-17);
    char delim[] = " ";
    char *ptr = strtok(buffer, delim);
    int user_id = atoi(ptr);
    bool found = false;
    for(int i=0;i<MAX_CLIENTS;i++){
        if(pending_public_key_request[i] == user_id){
            found = true;
            pending_public_key_request[i] = -1;
            break;
        }
    }
    if(found){
        vlog_msg("[INFO] Sending Public key to User ID: %d", user_id);
        send(client_socket, input, MAX_MESSAGE_LEN, 0);
    }
    else{
        vlog_msg("[WARN] Key Request NOT found Requester ID: %d", user_id);
    }
}

void write_group_client(char *input){
    log_msg("[INFO] Trying to send message in Group");
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
        group_invite_client(input); // user_id group_id
    }
    if(strncmp(input, "/group_invite_accept ", 21) == 0){
        group_invite_accept_client(input);
    }
    if(strncmp(input, "/init_group_dhxchg", 18) == 0){
        init_group_dhxchg_client(input);
    }
    if(strncmp(input, "/request_public_key ", 20) == 0){
        request_public_key_client(input);
    }
    if(strncmp(input, "/send_public_key ", 17) == 0){
        send_public_key_client(input);
    }
    if(strncmp(input, "/write_group ", 13) == 0){
        write_group_client(input);
    }

    // quit the server
    if(strncmp(input, "/quit", 5) == 0){
        quit_server();
    }
}