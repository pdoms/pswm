//MIT License
//Copyright (c) 2023 Paulo Doms <domspaulo@gmail.com>
//
//Permission is hereby granted, free of charge, to any person obtaining
//a copy of this software and associated documentation files (the
//"Software"), to deal in the Software without restriction, including
//without limitation the rights to use, copy, modify, merge, publish,
//distribute, sublicense, and/or sell copies of the Software, and to
//permit persons to whom the Software is furnished to do so, subject to
//the following conditions:
//
//The above copyright notice and this permission notice shall be
//included in all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
//LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
//WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


#define HM_IMPLEMENTATION
#include "hm.h"
#include "secure.h"
#include <sys/stat.h>
#include <time.h>
#include <byteswap.h>
#define STORE_NAME_CAP 32
#define INPUT_CAP 1024 
#define KEY_CAP 512
#define PW_CAP 512
#define TS_LEN 8
#define INT_LEN 4
#define LEN_OFFSET HASHLEN+SALTLEN 
#define LAST_UPDATE_OFFSET LEN_OFFSET+INT_LEN+TS_LEN
#define FILE_HEADER_LEN HASHLEN+SALTLEN+INT_LEN

typedef struct Store {
    hm* data;
    const char* path;
    FILE* fd;
    uint8_t* salt;
    uint8_t* hash;
    uint8_t* key;
    uint8_t* iv;
    unsigned char* aad;
    size_t data_len;
    int is_verified;
    unsigned long created;
    unsigned long last_update;

} Store;

void printid() {
    printf("pswm/>> ");
}

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

int file_exists(char* filename) {
    struct stat buffer;
    return (stat (filename, &buffer) == 0);
}

void long_to_bytes(unsigned long t, uint8_t bytes[TS_LEN]) {
    size_t i = 0;
    size_t shift = 56;
    for (i; i < TS_LEN; ++i) {
        bytes[i] = (t >> shift) & 0xFF;
        shift -= 8;
    }
}
unsigned long bytes_to_long (uint8_t bytes[TS_LEN]) {
    unsigned long result = 0;
    size_t shift = 56;
    for (int i = 0; i < TS_LEN; ++i) {
        result += (bytes[i] << shift);
        shift -= 8;
    }
    return result;
}


void int_to_bytes(unsigned long t, uint8_t bytes[INT_LEN]) {
    size_t i = 0;
    size_t shift = 24;
    for (i; i < INT_LEN; ++i) {
        bytes[i] = (t >> shift) & 0xFF;
        shift -= 8;
    }
}
uint32_t bytes_to_int(uint8_t bytes[INT_LEN]) {
    uint32_t result = 0;
    size_t shift = 24;
    for (int i = 0; i < INT_LEN; ++i) {
        result += (bytes[i] << shift);
        shift -= 8;
    }
}

char* open_store() {
    char* name = malloc(STORE_NAME_CAP);
    printf("pswm>> Type the name of the store (max. 32 characters/no white space or new line):\npswm>> ");
    scanf("%s", name);
    if (file_exists(name)) {
        fprintf(stderr, "pswm>> ERROR: store already exists.\n");
        exit(1);
    }
    char* pwu = getpass("pswm>> Provide Password: ");
    uint8_t* salt = init_random(SALTLEN);
    uint8_t hash_buf[HASHLEN];
    int rc = hash_pw(pwu, hash_buf, salt);
    if(ARGON2_OK != rc) {
        printf("pswm>> Error: %s\n", argon2_error_message(rc));
        exit(1);
    }
    FILE* file = fopen(name, "w+");
    if (file == NULL) {
        fprintf(stderr, "pswm>> ERROR: could not open file %s.\n", name);
        exit(1);
    }

    fwrite(salt, 1, SALTLEN, file);
    fwrite(hash_buf, 1, HASHLEN, file);
    unsigned long t = (unsigned long)time(NULL);
    uint8_t ts[TS_LEN*2];
    long_to_bytes(t, ts);
    long_to_bytes(t, ts+TS_LEN);
    unsigned char* key;
    unsigned int key_len = SHA256_LEN;
    hash_sha256(pwu, strlen(pwu), &key, &key_len);
    unsigned char aad[255];
    get_aad(aad);

    
    unsigned char* pre_iv;
    unsigned int pre_iv_len = SHA256_LEN;
    hash_sha256(name, strlen(name), &pre_iv, &pre_iv_len);

    unsigned char iv[16];
    memcpy(iv, pre_iv, 16);
    unsigned char ciphertext[32];
    unsigned char tag[16];
    int ciphertext_len = aes_encrypt(ts, 16, aad, strlen(aad), key, iv, ciphertext, tag); 
    unsigned char len_bytes[INT_LEN];
    int_to_bytes(ciphertext_len, len_bytes);
    fwrite(len_bytes, 1, INT_LEN, file);
    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);
    return name;
}

int load_store(Store* store, int dump) {
    FILE* fd = fopen(store->path, "r+");
    if (fseek(fd, 0, SEEK_END) < 0) return 0;
    long  flen = ftell(fd);
    if (flen < 0) return 0;
    if (fseek(fd, 0, SEEK_SET) < 0) return 0;
    uint8_t* file_buffer = (uint8_t*)malloc(sizeof(char) * flen);
    fread(file_buffer, 1, flen, fd);
    store->fd = fd;
    uint8_t* salt = malloc(SALTLEN);
    uint8_t* pw = malloc(HASHLEN);

    for (size_t i = 0; i < SALTLEN;++i) {
        salt[i] = file_buffer[i];
    }
    for (size_t i = 0; i < HASHLEN;++i) {
        pw[i] = file_buffer[SALTLEN+i];
    }
    

    char* inp = verify_pw(pw, salt);
    size_t bytes_len = flen - SALTLEN - HASHLEN;
    file_buffer += SALTLEN + HASHLEN;

    //read next four bytes for cipher len
    uint8_t len[INT_LEN];

    for (int i= 0; i < INT_LEN; ++i) {
        len[i] = file_buffer[i];
    }
    file_buffer += INT_LEN;
    

    int ciphertext_len = bytes_to_int(len);
    store->data_len = ciphertext_len;
    unsigned char aad[255];
    get_aad(aad);
    unsigned char tag[16];
    unsigned char* key;
    unsigned int key_len = SHA256_LEN;
    hash_sha256(inp, strlen(inp), &key, &key_len);
    int decryptedtext_len = 0;
    unsigned char* decryptedtext = malloc(ciphertext_len*2);
    

    unsigned char* pre_iv;
    unsigned int pre_iv_len = SHA256_LEN;
    hash_sha256(store->path, strlen(store->path), &pre_iv, &pre_iv_len);

    unsigned char iv[16];
    memcpy(iv, pre_iv, 16); 
    decryptedtext_len = aes_decrypt(file_buffer, 
            ciphertext_len, 
            aad, strlen(aad),
            tag, key, iv, 
            decryptedtext);
    
    uint8_t created[TS_LEN];
    for (int i = 0; i < TS_LEN; ++i) {
        created[i] = decryptedtext[i];
    }
    decryptedtext += TS_LEN;
    decryptedtext_len -= TS_LEN;

    uint8_t last_update[TS_LEN];
    for (int i = 0; i < TS_LEN; ++i) {
        last_update[i] = decryptedtext[i];
    }
    decryptedtext += TS_LEN;
    decryptedtext_len -= TS_LEN;
    


    store->created = bytes_to_long(created);
    store->last_update = bytes_to_long(last_update);

    Bytes bytes = bytes_new(decryptedtext, decryptedtext_len);
    int i = 0;
    if (dump) {
        printid();
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
    store->key = key;
    store->aad = aad;
    return 0;
}


void close_store(Store* store) {
    unsigned char* buffer;
    buffer = (unsigned char*)malloc(store->data_len*2);
    unsigned char created[TS_LEN];
    unsigned char last_update[TS_LEN];
    long_to_bytes(store->created, created);
    long_to_bytes(store->last_update, last_update);
    size_t buff_idx = 0;
    for (size_t i = 0; i < TS_LEN; ++i) {
        buffer[i] = created[i];
        buff_idx++;
    }
    for (size_t i = 0; i < TS_LEN; ++i) {
        buffer[buff_idx] = last_update[i];
        buff_idx++;
    }
    
    uint8_t WS = 32;
    uint8_t NL = 10;

    //serialize hashmap
    int buf_len = store->data_len*2;
    int ser_len = hm_serialize_cstr(store->data, buffer+buff_idx, buf_len, WS, NL); 
    //encrypt aes
    
    unsigned char* pre_iv;
    unsigned int pre_iv_len = SHA256_LEN;
    hash_sha256(store->path, strlen(store->path), &pre_iv, &pre_iv_len);

    unsigned char iv[16];
    memcpy(iv, pre_iv, 16); 

    int cipher_len = buff_idx+ser_len;
    //ciphertext can be longer than plaintext
    unsigned char* ciphertext = (unsigned char*)malloc(cipher_len*2);
    unsigned char tag[16];
    int ciphertext_len = aes_encrypt(buffer, cipher_len, store->aad, strlen(store->aad), store->key, iv, ciphertext, tag);
    
    unsigned char len_bytes[INT_LEN];
    int_to_bytes(ciphertext_len, len_bytes);
    fseek(store->fd, 0, SEEK_SET);
    //write first unencrypted data
    fwrite(store->salt, 1, SALTLEN, store->fd);
    fwrite(store->hash, 1, HASHLEN, store->fd);
    //length of data
    fwrite(len_bytes, 1, INT_LEN, store->fd);

    //encrypted timestamps and store contents
    fwrite(ciphertext, 1, ciphertext_len, store->fd);
    fclose(store->fd);
    free(buffer);
    free(ciphertext);
    free(store->salt);
    free(store->hash);
}




void usage() {
    printf("Usage: pswm <command | 'name of store'> [subcommand]\n");
    printf("\tCommands: \n");
    printf("\t\tnew ................. creates a new store\n");
    printf("\tSubcommands (follow store name):\n");
    printf("\t\tdump ................ prints contents of store\n");
    printf("\t\tset <key> <value> ... sets key value pair, overwrites value if already exists\n");
    printf("\t\tgen <key> ........... generates password and sets key value pair, overwrites value if already exists\n");
    printf("\t\tget <key> ........... gets value for key\n");
    printf("\t\tdel <key> ........... deletes entry by key\n");
    printf("\t\tdestroy ............. deletes storage\n");
    printf("\n\tNOTE: data is stored on disk password protected and encrypted. No warranty granted, use at your own risk.\n");
}

char* args_shift(int *argc, char ***argv)
{   
    if (*argc == 0) {
        usage();
        printf("ERROR: EXPECTED ARGUMENT\n");
        exit(1);
    } 
    char *result = **argv;
    (*argc) -= 1;
    (*argv) += 1;
    return result;
}


void set_item(Store* store, char* key, char* value) {
    assert(store->is_verified);
    size_t key_len = strlen(key);
    size_t value_len = strlen(value);
    store->data_len += key_len+value_len;
    hm_set(store->data, key, value);
    close_store(store);
}

void get_item(Store* store, char* key) {
    char* item = (char*)hm_get(store->data, key);
    printid(store->path);
    printf("%s : %s\n", key, item);
    close_store(store);
}

void delete_item(Store* store, char* key) {
    char* item = (char*)hm_get(store->data, key);
    size_t key_len = strlen(key);
    size_t value_len = strlen(item);
    store->data_len -= key_len+value_len;
    int result = hm_remove(store->data, key);
    assert(result == 1);
}




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
            .fd = NULL,
            .salt = NULL,
            .hash = NULL,
            .key = NULL,
            .aad = NULL,
            .data_len = 0,
            .is_verified = 0,
        };
        char* subcommand = args_shift(&argc, &argv);
        if (strcmp(subcommand, "destroy") == 0) {
            return remove(command);
        } 
        if (strcmp(subcommand, "dump") == 0) {
            load_store(&store, 1);
            return 0;
        }
        load_store(&store, 0);
        if (strcmp(subcommand, "set") == 0) {
            char* user = args_shift(&argc, &argv);
            char* pass = args_shift(&argc, &argv);
            set_item(&store, user, pass);
            return 0;
        }
        if (strcmp(subcommand, "get") == 0) {
            char* user = args_shift(&argc, &argv);
            get_item(&store, user);
            return 0;
        }
        if (strcmp(subcommand, "gen") == 0) {
            char* user = args_shift(&argc, &argv);
            char pass[15];
            generate_password(pass, 15);
            set_item(&store, user, pass);
            return 0;
        }
        if (strcmp(subcommand, "del") == 0) {
            char* user = args_shift(&argc, &argv);
            delete_item(&store, user);
            return 0;
        }
    } else {
        usage();
        printf("ERROR: EXPECTED ARGUMENT\n");
        exit(1);
    }
    return 0;
}
