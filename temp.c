#include "irc_interface.h"


int main() {

    char username[] = "rahul";

    // Initialize ncurses
    initscr();
    cbreak();
    // noecho();

    pthread_t thread_id; // Thread identifier

    // Create a new thread and pass it the argument
    int result = pthread_create(&thread_id, NULL, init__irc_interface, username);
    if (result != 0) {
        perror("Error creating thread");
        return 1;
    }

    sleep(2);
    add_irc_message("This is new");

    // Wait for the thread to finish
    result = pthread_join(thread_id, NULL);
    if (result != 0) {
        perror("Error joining thread");
        return 1;
    }

    endwin();

}
