#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <string.h>
#include "common.h"

#define SERVER_IP "127.0.0.1"
#define PORT 12345
#define BUFFER_SIZE 256
#define AES_KEY_SIZE 32
#define SALT_LENGTH 16 // Length of the salt (in bytes)
#define ITERATION_COUNT 10000 // Number of iterations

// Define a shared secret key for AES encryption/decryption (must match the server's key)
static const unsigned char aes_key[AES_KEY_SIZE] = "Your_AES_256_Key_Here";

// void derive_key(char *password, char *key) {
//     // Implement key derivation logic using OpenSSL's PBKDF2 function
//      // Generate a random salt
//     // unsigned char salt[SALT_LENGTH];
//     // if (RAND_bytes(salt, SALT_LENGTH) != 1) {
//     //     fprintf(stderr, "Error generating random salt\n");
//     //     return;
//     // }

//     // Derive the key using PBKDF2/HKDF
//     if (PKCS5_PBKDF2_HMAC(password, strlen(password), "salt", SALT_LENGTH, ITERATION_COUNT, EVP_sha256(), MAX_SYMMETRIC_KEY_LEN, key) != 1) {
//         fprintf(stderr, "Error deriving key using PBKDF2\n");
//         return;
//     }

//     // printf("Password %s\n", password);
//     // for (int i = 0; i < MAX_SYMMETRIC_KEY_LEN; i++) {
//     //     printf("%02x", key[i]);
//     // }
//     // printf("\n");
// }

void main(){
    char *pswd = "ThisIsssword";
    char key[1024];
    derive_key(pswd, key);
    char *key2;
    char pswd2[50];
    scanf("%s", pswd2);
    derive_key(pswd2, key2);
    printf("%ld",sizeof(key2));
    printf("Derived Key: %d\n",strcmp(key, key2));
}