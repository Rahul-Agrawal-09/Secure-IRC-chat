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
    lock();
    send(logged_users[my_index].user_socket, logged_users, sizeof(logged_users), 0);
    unlock();
}

void send_message(int index, void*content, int content_len){
    send(logged_users[index].user_socket, content, content_len, 0);
    kill(logged_users[index].pid, SIGUSR1);
}

void write_all_server(int my_index, char*input){
    BroadcastMessage bmsg;
    strncpy(bmsg.message, &input[11], sizeof(bmsg.message)-10);
    strncpy(bmsg.username, logged_users[my_index].username, sizeof(bmsg.username));
    for(int i=0;i<MAX_CLIENTS;i++){
        if( i != my_index && logged_users[i].user_socket > 0){
            send_message(i, &bmsg, sizeof(bmsg));
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
            for(int j=0;j<MAX_CLIENTS;j++)
                groups[i].group_users[j] = NULL;
            break;
        }
    }
    send(logged_users[my_index].user_socket, &groups[i], sizeof(Group), 0);
}


void group_invite_server(int my_index, char*input){
    
}


void init_irc_server(){
    // setting up the group details
    for(int i=0;i<MAX_GROUPS;i++)
        groups[i].group_id = -1;
    
}

void handle_irc_request_server(int my_index){
    // initialise the irc server
    init_irc_server();
    
    char command[MAX_MESSAGE_LEN];
    while(1==1){
        memset(command, '\0', sizeof(command));
        recv(logged_users[my_index].user_socket, command, sizeof(command), 0);
        if(strncmp("/who", command, 4) == 0){
            who_server(my_index);
        }
        if(strncmp("/write_all ", command, 11) == 0){
            write_all_server(my_index, command);
        }
        if(strncmp("/create_group ", command, 14) == 0){
            create_group_server(my_index, command);
        }
        if(strncmp("/create_group ", command, 14) == 0){
            group_invite_server(my_index, command);
        }


        // return if quit
        if(strncmp("/quit", command, 5) == 0){
            return;
        }
    }
}