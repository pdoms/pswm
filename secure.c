#include "secure.h"


static uint8_t CAPITALS[] = "ABCDEFGHIJKLMNOPQRSTUYWZ";  
static uint8_t LOWER[] = "abcdefghijklmnopqrstuywz";
static uint8_t NUMBERS[] = "0123456789";
static uint8_t SYMBOLS[] = "!@#$^&*?";

uint8_t* init_random(size_t num_bytes) {
   uint8_t* bytes = (uint8_t*)malloc(num_bytes);
   getrandom(bytes, num_bytes, 0);
   return bytes;
}

uint8_t get_random_uint8() {
   uint8_t* index = (uint8_t*)malloc(1);
   uint8_t* bytes = (uint8_t*)malloc(255);
   getrandom(bytes, 255, 0);
   getrandom(index, 1, 0);
   uint8_t rb = (uint8_t)bytes[index[0]];
   free(index);
   free(bytes);
   return rb;
}


void generate_password(char* pw, size_t pw_len) {
    size_t index;
    for (int i = 0; i < pw_len - 1; ++i) {
        uint8_t category = get_random_uint8() % NUM_CATEGORIES;
        switch (category) {
            case 0: 
                {
                    index = get_random_uint8() % NUM_LETTERS;
                    pw[i] = CAPITALS[index];
                    break;    
                }
            case 1: 
                {
                    index = get_random_uint8() % NUM_LETTERS;
                    pw[i] = LOWER[index];
                    break;    
                }
            case 2: 
                {
                    index = get_random_uint8() % NUM_NUMS;
                    pw[i] = NUMBERS[index];
                    break;
                }
            default: 
                {
                    index = get_random_uint8() % NUM_SYMBOLS;
                    pw[i] = SYMBOLS[index];
                }
        };
    }
    pw[pw_len] = '\0';
}



int hash_pw(char* pw, uint8_t* hash_buf, uint8_t* salt) {
    uint32_t pwdlen = strlen(pw);
    uint8_t* pwd = (uint8_t*)strdup(pw);
    uint32_t t_cost = 2;            // 2-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes

    argon2_context context = {
        hash_buf, /* output array, at least HASHLEN in size */
        HASHLEN, /* digest length */
        pwd, /* password array */
        pwdlen, /* password length */
        salt,  /* salt array */
        SALTLEN, /* salt length */
        NULL, 0, /* optional secret data */
        NULL, 0, /* optional associated data */
        t_cost, m_cost, parallelism, parallelism,
        ARGON2_VERSION_13, /* algorithm version */
        NULL, NULL, /* custom memory allocation / deallocation functions */
        /* by default only internal memory is cleared (pwd is not wiped) */
        ARGON2_DEFAULT_FLAGS
    };

    int rc = argon2id_ctx(&context);
    free(pwd);
    return rc;
}

void hash_sha256(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len)
{
	EVP_MD_CTX *mdctx;

	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handle_errors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handle_errors();

	if(1 != EVP_DigestUpdate(mdctx, message, message_len))
		handle_errors();

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		handle_errors();

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
		handle_errors();

	EVP_MD_CTX_free(mdctx);
}




char* verify_pw(uint8_t* pw, uint8_t* salt) {
    char* pwu = getpass("pswm>> password: ");
    uint8_t hash_buf[HASHLEN];
    int rc = hash_pw(pwu, hash_buf, salt);
    if(ARGON2_OK != rc) {
        printf("pswm>> Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    

    if (memcmp(pw, hash_buf, HASHLEN)!=0) {
        fprintf(stderr, "pswm>> ERROR: password is wrong\n");
        exit(1);
    }
    return pwu;
}



void handle_errors(void) {
    unsigned long err_code;

    printf("pswm>> ERROR: ");
    while (err_code = ERR_get_error()) {
        char *err = ERR_error_string(err_code, NULL);
        printf("%s\n", err);
    }
    abort();
}

int aes_encrypt(unsigned char* plaintext, int plaintext_len, 
        unsigned char *aad, int aad_len,
        unsigned char *key, 
        unsigned char *iv,
        unsigned char *ciphertext,
        unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    if (!(ctx=EVP_CIPHER_CTX_new())) {
        handle_errors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        handle_errors();
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
        handle_errors();
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        handle_errors();
    }

    if (aad && aad_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            handle_errors();
        }
    }

    if (plaintext) {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
            handle_errors();
        }
        ciphertext_len = len;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        handle_errors();
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        handle_errors();
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(unsigned char* ciphertext, int ciphertext_len,
        unsigned char* aad, int aad_len,
        unsigned char* tag, 
        unsigned char* key,
        unsigned char* iv,
        unsigned char* plaintext) {

    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handle_errors();
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        handle_errors();
    }

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
        handle_errors();
    }

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL,key,iv)) {
        handle_errors();
    }

    if (aad && aad_len > 0) {
        if (!EVP_DecryptUpdate(ctx,NULL, &len, aad, aad_len)) {
            handle_errors();
        }
    }

    if (ciphertext) {
        if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
            handle_errors();
        }
        plaintext_len = len;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        handle_errors();
    }

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    plaintext_len += len;
    return plaintext_len;
    //if (ret > 0) {
    //    plaintext_len += len;
    //    return plaintext_len;
    //} else {
    //    return -1;
    //}
}

int get_aad(unsigned char* buf) {
   int ret = getlogin_r(buf, AAD_IN_LEN);
   return ret;
}




