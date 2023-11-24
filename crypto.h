#include"common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>

int encrypt_data(char*aes_key, const char* plaintext, int plaintext_length, char* iv ,unsigned char* ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        pthread_exit(0);
    }

    // Initialise the encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        pthread_exit(0);
    }

    // Provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_length)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        pthread_exit(0);
    }
    ciphertext_len = len;

    // Finalise the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        pthread_exit(0);
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

int decrypt_data(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                 unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        pthread_exit(0);
    }

    // Initialize the decryption operation
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        pthread_exit(0);
    }

    // Provide the message to be decrypted, and obtain the plaintext output
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        pthread_exit(0);
    }
    plaintext_len = len;

    // Finalize the decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        pthread_exit(0);
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void derive_diffie_hellam(User *info){
    memset(info->public_key, '\0', BUFFER_SIZE);
    DH *dh = DH_get_2048_256();
    if (1 != DH_generate_key(dh)){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    const BIGNUM *pub_key = NULL;
    DH_get0_key(dh, &pub_key, NULL);
    char *hex_pub_key = BN_bn2hex(pub_key);
    strncpy(info->public_key, hex_pub_key, strlen(hex_pub_key));
    info->public_key_len = strlen(hex_pub_key);

    OPENSSL_free(hex_pub_key);
}

void compute_group_key(DhPublicKeys *public_keys, User*info){
    char *my_public_key = info->public_key;
    DH *dh = DH_get_2048_256();
    BIGNUM *server_pub_key = NULL;
    BN_hex2bn(&server_pub_key, my_public_key);

    unsigned char shared_secret[256];
    DH_compute_key(shared_secret, server_pub_key, dh);

    // Hash the shared secret to derive an AES key
    unsigned char aes_key[32]; // AES-256 key
    EVP_Digest(shared_secret, sizeof(shared_secret), aes_key, NULL, EVP_sha256(), NULL);
}