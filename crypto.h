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
#include <openssl/hmac.h>

DiffieHellamParams diffi_hellman_params;

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

bool hmac_verification(const unsigned char *message, size_t message_len, const unsigned char *key, size_t key_len, const unsigned char *hmac_received, unsigned int hmac_len)
{
  unsigned char *hmac = malloc(EVP_MAX_MD_SIZE);
  unsigned int computed_hmac_len;

  HMAC_CTX *hmac_ctx = HMAC_CTX_new();
  HMAC_Init_ex(hmac_ctx, key, key_len, EVP_sha256(), NULL);
  HMAC_Update(hmac_ctx, message, message_len);
  HMAC_Final(hmac_ctx, hmac, &computed_hmac_len);

  bool is_valid = (computed_hmac_len == hmac_len) && (memcmp(hmac_received, hmac, hmac_len) == 0);

  HMAC_CTX_free(hmac_ctx);
  free(hmac);

  return is_valid;
}


void generate_hmac(char *message, int message_len, char *key, int key_len,  char*hmac)
{
  HMAC_CTX *hmac_ctx = HMAC_CTX_new();

  HMAC_Init_ex(hmac_ctx, key, key_len, EVP_sha256(), NULL);
  HMAC_Update(hmac_ctx, message, message_len);
  
  unsigned int hmac_len;
  HMAC_Final(hmac_ctx, hmac, &hmac_len);

  HMAC_CTX_free(hmac_ctx);
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

    diffi_hellman_params;
    diffi_hellman_params.len = encrypt_data(BN_bn2hex(pub_key), hex_pub_key, strlen(hex_pub_key), NULL, diffi_hellman_params.encrypted_diffi_hellman_key);
    generate_hmac(hex_pub_key, strlen(hex_pub_key), BN_bn2hex(pub_key), strlen(BN_bn2hex(pub_key)), diffi_hellman_params.Hmac);

    strncpy(info->public_key, hex_pub_key, strlen(hex_pub_key));
    info->public_key_len = strlen(hex_pub_key);

    OPENSSL_free(hex_pub_key);
}

void compute_group_key(DhPublicKeys *public_keys, User*info){
    char *my_public_key = info->public_key;
    DH *dh = DH_get_2048_256();
    BIGNUM *server_pub_key = NULL;
    BN_hex2bn(&server_pub_key, my_public_key);

    // Decripting the diffi hellman variables
    char decrypted_diffi_hellman[BUFFER_SIZE];
    decrypt_data(diffi_hellman_params.encrypted_diffi_hellman_key,
    diffi_hellman_params.len, my_public_key, NULL, decrypted_diffi_hellman);
    unsigned char shared_secret[256];

    // compute the shared key
    DH_compute_key(shared_secret, server_pub_key, dh);

    // Hash the shared secret to derive an AES key
    unsigned char aes_key[32]; // AES-256 key
    EVP_Digest(shared_secret, sizeof(shared_secret), aes_key, NULL, EVP_sha256(), NULL);
    
    // send the computed key
    send_DH_key(shared_secret);
}