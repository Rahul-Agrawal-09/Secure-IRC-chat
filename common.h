#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <fcntl.h>

#define MAX_CLIENTS 10
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64
#define MAX_SYMMETRIC_KEY_LEN 256
#define CHAT_PORT 54321
#define KDC_PORT 12345
#define MAX_NONCE_LENGTH 50
#define BUFFER_SIZE 1024

#define MAX_NONCE INT32_MAX
#define CHAT_SERVER_USERNAME "NssChat123"

typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    unsigned char symmetric_key[MAX_SYMMETRIC_KEY_LEN];
    // char ticket[MAX_SYMMETRIC_KEY_LEN]; // Store user's ticket
    bool is_online;
} User;

typedef struct {
    User users[MAX_CLIENTS]; // Store user information including passwords, shared secrets, and tickets
    User server;
    int current_user_number;
} CommonData;
CommonData *common_data;

// typedef struct {
//     char username[MAX_USERNAME_LEN];
//     char password[MAX_PASSWORD_LEN];
//     char ticket[MAX_SYMMETRIC_KEY_LEN]; // Store user's ticket
// } MyInfo;

typedef struct {
    char client_username[MAX_USERNAME_LEN];
    char server_username[MAX_USERNAME_LEN];
    char nonce1 [MAX_NONCE_LENGTH];
} NsMessage1;

// typedef struct {
//     char encrypted_message[];
// }

// Generate a random nonce within the specified range
int generate_nonce() {
    // uniqie number every time
    srand(time(NULL));
    int nonce = rand() % MAX_NONCE;
    return nonce;
}

const char* characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
char random_username[MAX_USERNAME_LEN];
char* generate_username(int username_length) {
    if(username_length>=MAX_USERNAME_LEN)
        perror("Length of Username no supported.");
    // srand(time(NULL));
    for (int i = 0; i < username_length; i++) {
        random_username[i] = characters[rand() % 62];
    }
    // random_username[username_length] = '\0';
    return random_username;
}

// map shared space for common structure
void* map_common_space(){
    const char *file_path = "common_data.txt";
    const size_t size = sizeof(CommonData);
    
    // Create or open the file
    int fd = open(file_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    // Truncate the file to the desired size
    if (ftruncate(fd, size) == -1) {
        perror("ftruncate");
        close(fd);
        exit(EXIT_FAILURE);
    }
    // Map the file into memory using mmap
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(EXIT_FAILURE);
    }
    return mem;
}

