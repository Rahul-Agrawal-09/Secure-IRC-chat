#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "kdc.h"

LoggedUser logged_users[MAX_CLIENTS];
Group groups[MAX_GROUPS];
pthread_mutex_t logged_users_mutex = PTHREAD_MUTEX_INITIALIZER;

void lock(){
    pthread_mutex_lock(&logged_users_mutex);
}

void unlock(){
    pthread_mutex_unlock(&logged_users_mutex);
}

void who_server(int my_index){
    send(logged_users[my_index].user_socket, logged_users, sizeof(logged_users), 0);
}

void send_message(int index, Message *content){
    send(logged_users[index].user_socket, content, sizeof(Message), 0);
    kill(logged_users[index].pid, SIGUSR1);
}

void write_all_server(int my_index, char*input){
    Message bmsg;
    strncpy(bmsg.message_type, "BCAST", sizeof(bmsg.message_type));
    strncpy(bmsg.message, &input[11], sizeof(bmsg.message)-11);
    strncpy(bmsg.username, logged_users[my_index].username, sizeof(bmsg.username));
    for(int i=0;i<MAX_CLIENTS;i++){
        if( i != my_index && logged_users[i].user_socket > 0){
            send_message(i, &bmsg);
        }
    }
}

void create_group_server(int my_index, char*input){
    int i;
    for(i=0;i<MAX_GROUPS;i++){
        if(groups[i].group_id < 0){
            strncpy(groups[i].group_name, &input[14], sizeof(groups[i].group_name));
            groups[i].group_id = get_id();
            groups[i].admin = logged_users[my_index].user;
            for(int j=0;j<MAX_CLIENTS;j++){
                groups[i].invited_users[j] = NULL;
                groups[i].accepted_users[j] = NULL;
            }
            break;
        }
    }
    send(logged_users[my_index].user_socket, &groups[i], sizeof(Group), 0);
}

int get_group_index(int group_id){
    for(int i=0; i<MAX_GROUPS;i++){
        if(groups[i].group_id == group_id){
            return i;
            break;
        }
    }
    printf("[WARN] Group:%d does not exist\n", group_id);
    return -1;
}

int get_logged_user_index(int user_id){
    for(int i=0; i<MAX_CLIENTS;i++){
        if(logged_users[i].user_id == user_id){
            return i;
            break;
        }
    }
    printf("[WARN] User:%d does not exist\n", user_id);
    return -1;
}

void group_invite_server(int my_index, char*input){
    strtok(input, " ");
    int user_id = atoi(strtok(NULL, " "));
    int group_id = atoi(strtok(NULL, " "));
    printf("Invitation Group:%d User:%d\n", group_id, user_id);
    
    int group_index = get_group_index(group_id);
    int user_index = get_logged_user_index(user_id);
    if(user_index==-1 || group_index==-1){
        Message msg;
        strncpy(msg.message_type, "WARN", sizeof(msg.message_type));
        sprintf(msg.message, "User:%d or Group:%d does not exist", user_id, group_id);
        send_message(my_index, &msg);
        return;
    }
    for(int i=0;i<MAX_CLIENTS;i++){
        if(groups[group_index].invited_users[i] == NULL){
            groups[group_index].invited_users[i] = logged_users[user_index].user;
            break;
        }
    }

    Message msg;
    strncpy(msg.message_type, "INVITE", sizeof(msg.message_type));
    strncpy(msg.username, logged_users[my_index].username, sizeof(msg.username));
    msg.group_id = group_id;
    sprintf(msg.message, "Invitation of Group:%s[ID:%d] from User:%s[ID:%d]", 
        groups[group_index].group_name, group_id, logged_users[my_index].username, logged_users[my_index].user_id);
    send_message(user_index, &msg);
    return;
}

void group_invite_accept_server(int my_index, char*input){
    strtok(input, " ");
    int group_id = atoi(strtok(NULL, " "));
    int group_index = get_group_index(group_id);
    if(group_index<0)
        return;
    bool is_invited = false;
    char status[] = "SUCCESS";
    Group *group = &groups[group_index];
    for(int i=0;i<MAX_CLIENTS;i++){
        if(group->invited_users[i]->user_id == logged_users[my_index].user_id){
            is_invited = true;
            group->accepted_users[i] = group->invited_users[i];
            break;
        }
    }
    if(!is_invited){
        printf("User is not Invited\n");
        return;
    }
    int admin_index = get_logged_user_index(group->admin->user_id);
    if(admin_index>=0){
        Message msg;
        msg.group_id = group_id;
        strncpy(msg.message_type, "INFO", sizeof(msg.message_type));
        strncpy(msg.username, logged_users[my_index].username, sizeof(msg.username));
        sprintf(msg.message, "User:%s[ID:%d] accepted invite for Group:%s[ID:%d]",
            msg.username, logged_users[my_index].user_id, group->group_name, group->group_id);
        send_message(admin_index, &msg);
        printf("%s\n", msg.message);
    }
    else{
        printf("Group:%s Admin Not online\n", group->group_name);
    }
}


void init_group_dhxchg_server(int my_index, char*input){
    strtok(input, " ");
    int group_id = atoi(strtok(NULL, " "));
    printf("Diffie-Hellman Key Exchange for group: %d\n", group_id);
    Message msg;
    DhPublicKeys public_keys [MAX_CLIENTS];
    strncpy(msg.message_type, "DIFI", sizeof(msg.message_type));
    strncpy(msg.username, logged_users[my_index].username, sizeof(msg.username));
    sprintf(msg.message, "Group Diffie-Hellman Key Exchange initiated by %s for group ID %d.", msg.username, msg.group_id);
    msg.group_id = group_id;
    int group_index = get_group_index(group_id);
    if(group_index<0)
        return;

    int admin_index =get_logged_user_index(groups[group_index].admin->user_id); 
    if(admin_index>=0 && admin_index != my_index){
        send_message(admin_index, &msg);
        strncpy(public_keys[MAX_CLIENTS-1].public_key, groups[group_index].admin->public_key, BUFFER_SIZE);
        public_keys[MAX_CLIENTS-1].is_valid = true;
    }
    for(int i=0;i<MAX_CLIENTS;i++){
        if(groups[group_index].accepted_users[i] != NULL){
            int index = get_logged_user_index(groups[group_index].accepted_users[i]->user_id);
            if(index>=0 && index!=my_index){
                send_message(index, &msg);
            }
            strncpy(public_keys[i].public_key, groups[group_index].accepted_users[i]->public_key, BUFFER_SIZE);
            public_keys[i].is_valid = true;
        }
        else{
            strncpy(public_keys[i].public_key, "NULL", BUFFER_SIZE);
            public_keys[i].is_valid = false;
        }
    }
    groups[group_index].diffi_helman_done = true;
    send(logged_users[my_index].user_socket, public_keys, sizeof(public_keys), 0);
}


void request_public_key_server(int my_index, char*input){
    strtok(input, " ");
    int user_id = atoi(strtok(NULL, " "));
    int user_index = get_logged_user_index(user_id);
    if(user_index<0)
        return;
    Message msg;
    strncpy(msg.username, logged_users[my_index].username, sizeof(msg.username));
    msg.group_id = logged_users[my_index].user_id;
    strncpy(msg.message_type, "PUB_REQUEST", sizeof(msg.message_type));
    sprintf(msg.message, "Public key requested by %s[ID:%d]", logged_users[my_index].username, logged_users[my_index].user_id);
    printf("%s\n", msg.message);
    send_message(user_index, &msg);
}


void send_public_key_server(int my_index, char*input){
    strtok(input, " ");
    int user_id = atoi(strtok(NULL, " "));
    int user_index = get_logged_user_index(user_id);
    if(user_index<0)
        return;
    Message msg;
    strncpy(msg.message_type, "PUB_RESPONSE", sizeof(msg.message_type));
    sprintf(msg.message, "Public key received from user: %s [uid:%d]", logged_users[my_index].username, logged_users[my_index].user_id);
    sprintf(msg.username, logged_users[my_index].username, sizeof(msg.username));
    send_message(user_index, &msg);
}

void write_group_server(int my_index, char* input){
    strtok(input, " ");
    int group_id = atoi(strtok(NULL, " "));
    char message[MAX_MESSAGE_LEN];
    strncpy(message, &input[18], sizeof(message)-18);
    int group_index = get_group_index(group_id);
    Message msg;
    if(!groups[group_index].diffi_helman_done){
        strncpy(msg.message_type, "WARN", sizeof(msg.message_type));
        sprintf(msg.message, "Group ID: %d Diffie-Hellman Key Exchange NOT performed cannot send message", group_id);
        send_message(my_index, &msg);
        return;
    }
    if(group_index < 0){
        strncpy(msg.message_type, "WARN", sizeof(msg.message_type));
        sprintf(msg.message, "Group ID: %d DOES NOT exist", group_id);
        send_message(my_index, &msg);
        return;
    }
    msg.group_id = group_id;
    strncpy(msg.message_type, "GCAST", sizeof(msg.message_type));
    strncpy(msg.message, message, sizeof(msg.message));
    strncpy(msg.username, logged_users[my_index].username, sizeof(msg.username));
    for(int i=0;i<MAX_CLIENTS;i++){
        if(groups[group_index].invited_users[i] != NULL){
            int member_index = get_logged_user_index(groups[group_index].invited_users[i]->user_id);
            if(member_index > 0)
                send_message(member_index, &msg);
        }
    }
    int admin_index = get_logged_user_index(groups[group_index].admin->user_id);
    if(admin_index>=0 && admin_index!=my_index){
        send_message(admin_index, &msg);
    }
}


void init_irc_server(){
    // setting up the group details
    for(int i=0;i<MAX_GROUPS;i++){
        groups[i].group_id = -1;
        groups[i].diffi_helman_done = false;
    }

}

void handle_irc_request_server(int my_index){
    // initialise the irc server
    init_irc_server();
    
    char command[MAX_MESSAGE_LEN];
    while(1==1){
        memset(command, '\0', sizeof(command));
        recv(logged_users[my_index].user_socket, command, sizeof(command), 0);
        lock();
        if(strncmp("/who", command, 4) == 0){
            who_server(my_index);
        }
        if(strncmp("/write_all ", command, 11) == 0){
            write_all_server(my_index, command);
        }
        if(strncmp("/create_group ", command, 14) == 0){
            create_group_server(my_index, command);
        }
        if(strncmp("/group_invite ", command, 14) == 0){
            group_invite_server(my_index, command);
        }
        if(strncmp("/group_invite_accept ", command, 21) == 0){
            group_invite_accept_server(my_index, command);
        }
        if(strncmp("/init_group_dhxchg", command, 18) == 0){
            init_group_dhxchg_server(my_index, command);
        }
        if(strncmp("/request_public_key ", command, 20) == 0){
            request_public_key_server(my_index, command);
        }
        if(strncmp("/send_public_key ", command, 17) == 0){
            send_public_key_server(my_index, command);
        }
        if(strncmp("/write_group ", command, 13) == 0){
            write_group_server(my_index, command);
        }

        // return if quit
        if(strncmp("/quit", command, 5) == 0){
            unlock();
            return;
        }
        unlock();
    }
}