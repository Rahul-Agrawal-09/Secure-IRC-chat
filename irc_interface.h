#include <ncurses.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "crypto.h"

#define MAX_MESSAGE_LEN 256
WINDOW *chatwin;
pthread_mutex_t myMutex = PTHREAD_MUTEX_INITIALIZER;

void handle_irc_request_client(char* input);

void log_msg(char* msg){
    pthread_mutex_lock(&myMutex);
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    wprintw(chatwin, "[%d-%02d-%02d %02d:%02d:%02d] %s\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, msg);
    wrefresh(chatwin);
    pthread_mutex_unlock(&myMutex);
}

void vlog_msg(const char *fmt, ...){
    char buffer[MAX_MESSAGE_LEN];
    va_list args;
    va_start(args, fmt);
    int rc = vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    log_msg(buffer);
}

char* submit_input(char* input){
    // currently only showing the input
    handle_irc_request_client(input);
}

void* init__irc_interface(void* arg){

    char* username = ((char *)arg);

    int irc_rows, irc_cols;
    getmaxyx(stdscr, irc_rows, irc_cols);

    // Calculate window sizes and positions
    int height, width, start_y, start_x;
    height = irc_rows; width = irc_cols; start_y = start_x = 0;

    // Create windows
    chatwin = newwin(height - 3, width, start_y, start_x);
    WINDOW *inputwin = newwin(3, width, height - 3, start_x);
    scrollok(chatwin, TRUE);  // Enable scrolling for chat window

    // box(chatwin, 0, 0);       // Draw a box around the chat window
    box(inputwin, 0, 0);      // Draw a box around the input window

    // Main loop
    while (1) {
        // Display a prompt in the input window
        mvwprintw(inputwin, 1, 1, "[%s]: ", username);
        wrefresh(inputwin);

        // Get input
        char msg[256];
        wgetnstr(inputwin, msg, MAX_MESSAGE_LEN);

        // Handle input (display in chat window)
        if(strlen(msg) > 0)
            submit_input(msg);

        // Clear input window
        werase(inputwin);
        box(inputwin, 0, 0);   // Draw the box again after erase
        wrefresh(inputwin);

        // Check for exit condition
        if (strncmp(msg, "/quit", 5) == 0) {
            break;
        }
    }

    // Clean up
    delwin(chatwin);
    delwin(inputwin);

    return NULL;
}