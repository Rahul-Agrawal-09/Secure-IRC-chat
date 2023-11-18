#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "kdc.h"

LoggedUser logged_users[MAX_CLIENTS];
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

void write_all_server(){
    
}

void create_group_server(){

}

void handle_irc_request_server(int my_index){
    char command[32];
    while(1==1){
        memset(command, '\0', sizeof(command));
        recv(logged_users[my_index].user_socket, command, sizeof(command), 0);
        if(strncmp("/who", command, 4) == 0){
            who_server(my_index);
        }

        // return if quit
        if(strncmp("/quit", command, 5) == 0){
            return;
        }
    }
}