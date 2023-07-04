#ifndef _SECURE_H
    #define _SECURE_H

#include "argon2.h"
#include "openssl/evp.h"
#include <sys/random.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define HASHLEN 32
#define SALTLEN 16
#define SHA256_LEN 32
#define AAD_IN_LEN 256
#define NUM_LETTERS 26
#define NUM_NUMS 10
#define NUM_SYMBOLS 8 
#define NUM_CATEGORIES 4

//returns num_bytes of random bytes
uint8_t* init_random(size_t num_bytes);

uint8_t get_random_uint8();

//////ARGON2
//asks for user password, and compares the argon2id hash with it
char* verify_pw(uint8_t* pw, uint8_t* salt); 
//argon2 hashes a password
int hash_pw(char* pw, uint8_t* hash_buf, uint8_t* salt);

////SHA256
//hashes the password to be used for aes
void hash_sha256(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len);

////////AES
//from https://stackoverflow.com/questions/9889492/how-to-do-encryption-using-aes-in-openssl
//error handler
void handle_errors(void);


int aes_encrypt(unsigned char* plaintext, int plaintext_len, 
        unsigned char *aad, int aad_len,
        unsigned char *key, 
        unsigned char *iv,
        unsigned char *ciphertext,
        unsigned char *tag); 

int aes_decrypt(unsigned char* ciphertext, int ciphertext_len,
        unsigned char* aad, int aad_len,
        unsigned char* tag, 
        unsigned char* key,
        unsigned char* iv,
        unsigned char* plaintext);

int get_aad(unsigned char* buf);
int get_iv();

void generate_password(char* pw, size_t pw_len);






#endif //_SECURE_H
