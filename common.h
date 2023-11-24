#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define MAX_CLIENTS 10
#define MAX_GROUPS 20
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 64
#define MAX_SYMMETRIC_KEY_LEN 256
#define CHAT_PORT 54321
#define KDC_PORT 54322
#define MAX_NONCE_LENGTH 50
#define MAX_SESSION_KEY_LEN 32
#define SESSION_KEY_LEN 16
#define BUFFER_SIZE 1024
#define SALT_LENGTH 16 // Length of the salt (in bytes)
#define ITERATION_COUNT 10000 // Number of iterations
#define ENCRYPTED_TICKET_LEN 256
#define SERVER_IP "127.0.0.1"
#define MAX_MESSAGE_LEN 256
#define MAX_PASSWORD_ATTEMPTS 3

#define MAX_NONCE INT32_MAX
#define CHAT_SERVER_USERNAME "NssChat123"

typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    unsigned char symmetric_key[MAX_SYMMETRIC_KEY_LEN];
    int user_id;
    char public_key[BUFFER_SIZE];
    int public_key_len;
    // char ticket[MAX_SYMMETRIC_KEY_LEN]; // Store user's ticket
} User;

typedef struct {
    int password_attemps;
    bool blocked;
} LoginProtection;

typedef struct {
    User users[MAX_CLIENTS]; // Store user information including passwords, shared secrets, and tickets
    User server;
    LoginProtection login_protection[MAX_CLIENTS];
    // int current_user_number;
} CommonData;
CommonData *common_data;

typedef struct {
    char client_username[MAX_USERNAME_LEN];
    char server_username[MAX_USERNAME_LEN];
    char nonce1 [MAX_NONCE_LENGTH];
} NsMessage1;

typedef struct {
    char session_key[MAX_SESSION_KEY_LEN];
    char requesting_username[MAX_USERNAME_LEN];
} Ticket;

typedef struct {
    char nonce1 [MAX_NONCE_LENGTH];
    char server_username [MAX_USERNAME_LEN];
    char session_key[MAX_SESSION_KEY_LEN];
    size_t encrypted_ticket_len;
    char encrypted_ticket[ENCRYPTED_TICKET_LEN];
} NsMessage2;

typedef struct {
    char decremented_nonce2 [MAX_NONCE_LENGTH];
    char nonce3 [MAX_NONCE_LENGTH];
} Challenge;

typedef struct {
    char username[MAX_USERNAME_LEN];
    int user_socket;
    int user_id;
    User *user;
    pid_t pid;
} LoggedUser;

typedef struct{
    char message_type[32];
    char username[MAX_USERNAME_LEN];
    char message[MAX_MESSAGE_LEN];
    int group_id; 
} Message;

typedef struct{
    char group_name[MAX_USERNAME_LEN];
    int group_id;
    bool diffi_helman_done;
    User *admin;
    User *invited_users[MAX_CLIENTS];
    User *accepted_users[MAX_CLIENTS];
} Group;

typedef struct{
    char public_key[BUFFER_SIZE];
    bool is_valid;
} DhPublicKeys;

typedef struct{
    char Hmac[BUFFER_SIZE];
    char encrypted_diffi_hellman_key[BUFFER_SIZE];
    int len;
} DiffieHellamParams;

// Generate a random nonce within the specified range
int generate_nonce() {
    // uniqie number every nano second
    struct timespec time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time);
    srand(time.tv_nsec);
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

// Function to perform PBKDF key derivation
void derive_key(char *password, char *key) {

    // Derive the key using PBKDF2/HKDF
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), "ThisIsSalt", SALT_LENGTH, ITERATION_COUNT, EVP_sha256(), MAX_SYMMETRIC_KEY_LEN, key) != 1) {
        fprintf(stderr, "Error deriving key using PBKDF2\n");
        return;
    }

}

int id = 1000;
int get_id(){
    return ++id;
}

void send_DH_key(unsigned char* shared_key){
    return;
}