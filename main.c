#define HM_IMPLEMENTATION
#include "hm.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "argon2.h"
#include <sys/random.h>
#include <sys/stat.h>

#define STORE_NAME_CAP 32
#define INPUT_CAP 1024 
#define KEY_CAP 512
#define PW_CAP 512
#define HASHLEN 32
#define SALTLEN 16

typedef struct Store {
    hm* data;
    const char* path; 
    uint8_t* salt;
    uint8_t* hash;
    int is_verified;
} Store;

void printid(const char* id) {
    printf("pswm/%s>> ", id);
}
//typedef struct S_View {
//    char* data;
//    size_t count;
//} S_View;
//
//S_View S_View_readn(S_View* src, size_t n) {
//    S_View result = {.data = src->data, .count = n};
//    if (n < src->count) {
//        src->count -= n+1;
//        src->data += n+1;
//    } else {
//        src->count -= n;
//        src->data += n;
//    }
//    return result;
//}
//
//void S_View_cutn(S_View* src, size_t n) {
//    if (n < src->count) {
//        src->count -= n+1;
//        src->data += n+1;
//    } else {
//        src->count -= n;
//        src->data += n;
//    }
//}
//
//S_View S_View_until(S_View* src, char p) {
//    size_t i = 0;
//    while (i < src->count && src->data[i] != p) {
//        i += 1;
//    }
//    S_View result = {.data = src->data, .count = i};
//    if (i < src->count) {
//        src->count -= i+1;
//        src->data += i+1;
//    } else {
//        src->count -= i;
//        src->data += i;
//    }
//    return result;
//}
//
//
//char* S_View_to_cstr(S_View src) {
//    src.data[src.count] = '\0';
//    return src.data;
//}
//char* S_View_to_cstr_(S_View *src) {
//    src->data[src->count] = '\0';
//    return src->data;
//}
//

typedef struct {
    uint8_t* bytes;
    size_t len;
} Bytes;

Bytes bytes_new(uint8_t* data, size_t len) {
    return (Bytes) {
        .bytes = data,
        .len = len
    };
}

Bytes bytes_until_delim(Bytes* bytes, uint8_t p) {
    size_t i = 0;
    while (i < bytes->len && bytes->bytes[i] != p) {
        i += 1;
    }
    Bytes result = {.bytes = bytes->bytes, .len = i};
    if (i < bytes->len) {
        bytes->len -= i+1;
        bytes->bytes += i+1;
    } else {
        bytes->len -= i;
        bytes->bytes += i;
    }
    return result;
}

char* bytes_to_cstr(Bytes* bytes) {
    bytes->bytes[bytes->len] = '\0';
    return bytes->bytes;
}

void bytes_dump(Bytes* bytes) {
    size_t i = 0;
    for (i; i < bytes->len; ++i) {
        printf("%c", bytes->bytes[i]);
    }
    printf("\n");
}


uint8_t* init_random(size_t num_bytes) {
   uint8_t* bytes = (uint8_t*)malloc(num_bytes);
   getrandom(bytes, num_bytes, 0);
   return bytes;
}

int file_exists(char* filename) {
    struct stat buffer;
    return (stat (filename, &buffer) == 0);
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

char* open_store() {
    char* name = malloc(STORE_NAME_CAP);
    printf("pswm>> Type the name of the store (max. 32 characters):\n");
    scanf("%s", name);
    if (file_exists(name)) {
        fprintf(stderr, "ERROR: store already exists.\n");
        exit(1);
    }
    char* pwu = getpass("pswm>> Provide Password: ");
    printf("You typed: '%s'\n", pwu);
    uint8_t* salt = init_random(SALTLEN);
    uint8_t hash_buf[HASHLEN];
    int rc = hash_pw(pwu, hash_buf, salt);
    if(ARGON2_OK != rc) {
        printf("Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    printf("Calculated Salt\n");
    for( int i=0; i<SALTLEN; ++i ) printf( "%02x", salt[i]); printf( "\n" );
    printf("Calculated Hash\n");
    for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash_buf[i]); printf( "\n" );
    FILE* file = fopen(name, "w+");
    if (file == NULL) {
        fprintf(stderr, "ERROR: could not open file %s.\n", name);
        exit(1);
    }

    fwrite(salt, 1, SALTLEN, file);
    fwrite(hash_buf, 1, HASHLEN, file);
    fclose(file);
    return name;
}

void verify_pw(uint8_t* pw, uint8_t* salt) {
    char* pwu = getpass("pswm>> password: ");
    printf("you typed '%s'\n", pwu);
    uint8_t hash_buf[HASHLEN];
    int rc = hash_pw(pwu, hash_buf, salt);
    if(ARGON2_OK != rc) {
        printf("Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    
    printf("TO MATCH Hash\n");
    for( int i=0; i<HASHLEN; ++i ) printf( "%02x", hash_buf[i]); printf( "\n" );
    //for( int i=0; i<HASHLEN; ++i ) printf( "%02x", pw[i]); printf( "\n" );

    if (memcmp(pw, hash_buf, HASHLEN)!=0) {
        fprintf(stderr, "ERROR: password is wrong\n");
        exit(1);
    } 
}


int load_store(Store* store, int dump) {
    FILE* fd = fopen(store->path, "r");
    if (fseek(fd, 0, SEEK_END) < 0) return 0;
    long  flen = ftell(fd);
    if (flen < 0) return 0;
    if (fseek(fd, 0, SEEK_SET) < 0) return 0;
    uint8_t* file_buffer = (uint8_t*)malloc(sizeof(char) * flen);
    fread(file_buffer, 1, flen, fd);
    fclose(fd);
    uint8_t salt[SALTLEN];
    uint8_t pw[HASHLEN];
    //for (size_t i =0; i < flen;++i) {
    //    printf("%02x", file_buffer[i]);
    //}
    //printf("\n");



    for (size_t i = 0; i < SALTLEN;++i) {
        salt[i] = file_buffer[i];
    }
    //printf("LOADED Salt\n");
    //for (size_t i = 0; i < SALTLEN;++i) {
    //    printf("%02x",salt[i]);
    //}
    //printf("\n");

    for (size_t i = 0; i < HASHLEN;++i) {
        pw[i] = file_buffer[SALTLEN+i];
    }
    //printf("LOADED Hash\n");
    //for (size_t i = 0; i < HASHLEN;++i) {
    //    printf("%02x",pw[i]);
    //}
    //printf("\n");






    verify_pw(pw, salt);
    size_t bytes_len = flen - SALTLEN - HASHLEN;
    file_buffer += SALTLEN + HASHLEN;
    Bytes bytes = bytes_new(file_buffer, bytes_len);
    int i = 0;
    if (dump) {
        printid(store->path);
        printf("\n");
    }
    while (bytes.len > 0) {
        Bytes key = bytes_until_delim(&bytes, (char)' ');    
        Bytes value = bytes_until_delim(&bytes, (char)'\n');
        char* key_str = bytes_to_cstr(&key);
        char* value_str = bytes_to_cstr(&value);
        hm_set(store->data, key_str, value_str);
        if (dump) {
            printf("\t%d %s : %s\n", i, key_str, value_str);
        }
        i++;
    }
    store->salt = salt;
    store->hash = pw;
    store->is_verified = 1;
    return 0;
}

void usage() {
    printf("Usage: pswm <command>\n");
    printf("\topen ..... creates a new store\n");
}

char* args_shift(int *argc, char ***argv)
{
    assert(*argc > 0);
    char *result = **argv;
    (*argc) -= 1;
    (*argv) += 1;
    return result;
}


void set_item(Store* store, char* key, char* value) {
    assert(store->is_verified);
    size_t key_len = strlen(key) + 1;
    size_t value_len = strlen(value) + 1;
    uint8_t* line = (uint8_t*)malloc(key_len+value_len);
    size_t i = 0;
    key[strlen(key)] = ' ';
    value[strlen(value)] = '\n';
    for (i; i < key_len;++i) {
        printf("%c", key[i]);
        line[i] = (uint8_t)key[i];
    }
    for (i=0; i < value_len;++i) {
        printf("%c", value[i]);
        line[i+key_len] = (uint8_t)value[i];
    }
    for (i=0; i < key_len+value_len;++i) {
        printf("%c", line[i]);
    }

    FILE* fd = fopen(store->path, "a");
    if (fd == NULL) {
        fprintf(stdin, "ERROR: could not open file%s\n", store->path);
        exit(1);
    }
    fwrite(line, 1, key_len+value_len, fd);
    fclose(fd);
    free(line);
}

void get_item(Store* store, char* key) {
    char* item = (char*)hm_get(store->data, key);
    printid(store->path);
    printf("%s : %s\n", key, item);
}

void delete_item() {}




int main(int argc, char **argv) {
    //get rid of programm name 
    args_shift(&argc, &argv);
    if (argc > 0) {
        char* command = args_shift(&argc, &argv);
        if (strcmp(command, "new") == 0 && argc == 0) {
            char* name = open_store();
            char name_cpy[STORE_NAME_CAP];
            strcpy(name_cpy, name);
            free(name);
            return 0;
        } 
        Store store = {
            .data = hm_new(),
            .path = command,
            .salt = NULL,
            .hash = NULL,
            .is_verified = 0,
        };
        char* subcommand = args_shift(&argc, &argv);
        if (strcmp(subcommand, "dump") == 0) {
            load_store(&store, 1);
            return 0;
        }
        load_store(&store, 0);
        if (strcmp(subcommand, "set") == 0) {
            char* user = args_shift(&argc, &argv);
            char* pass = args_shift(&argc, &argv);
            printf("USER: '%s'; PASS: '%s'\n", user, pass);
            set_item(&store, user, pass);
            return 0;
        }
        if (strcmp(subcommand, "get") == 0) {
            char* user = args_shift(&argc, &argv);
            printf("USER: '%s'\n", user);
            get_item(&store, user);
            return 0;
        }
    }
    //char store_id[STORE_NAME_CAP];
    //printf("pswm>> Please provide store id:\npswm>> ");
    //scanf("%s", store_id);
    //Store store = {
    //    .data = hm_new(),
    //    .path = store_id,
    //    .salt = NULL,
    //    .hash = NULL,
    //    .is_verified = 0,
    //};
    //run(&store);
    return 0;
}
