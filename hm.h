// Implementation taken from:
// https://benhoyt.com/writings/hash-table-in-c/
// https://github.com/benhoyt/ht
// Taken because I wanted to learn about it but ended up mostly typing over the 
// implementation (tutorial)

#ifndef _HM_H
    #define _HM_H

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// entry, for now we keep it defined
typedef struct {
    const char* key; //key will be null if mem location is empty
    void* value;
} hm_entry;

// main hash table struct
typedef struct {
    hm_entry* entries;
    size_t capacity;
    size_t length;
} hm;

//create new hashmap
extern hm* hm_new(void);

//destroy hash table
extern void hm_destroy(hm *map);

//get item by key
extern void* hm_get(hm* map, const char* key);

//sets new entry as key value (neither can be NULL)
//if key present, override, else new created
//returns address of newly created key
extern const char* hm_set(hm* map, const char* key, void* value);

//removes entry by key return 1 if deletion success and 0 if not item not found
extern int hm_remove(hm* map, char* key);


// get length of table
extern size_t hm_len(hm* map);


// hm iterator
typedef struct {
    const char* key;
    void* value;
    hm* _map;
    size_t _index; 
} hmi;

//get iterator 
extern hmi hm_iterator(hm* map);

//get next item in iterator
//returns 0 if no more items left
//hm can't be updated while iterating
extern int hm_iter_next(hmi* iter); 

//prints to whole hashmap to the screen
extern void hm_dump(hm* map, int idx);

//serializes the map if value is char*, and returns the buffer length
extern int hm_serialize_cstr(hm* map, uint8_t* buffer, int buffer_len, uint8_t kv_delim, uint8_t entry_delim);

#endif //_HM_H

#ifdef HM_IMPLEMENTATION



#define INITIAL_CAPACITY 16;
#define FNV_OFFSET 14695981039346656037UL
#define FNV_PRIME 1099511628211UL

hm* hm_new(void) 
{
    
    hm* map = malloc(sizeof(hm));
    if (map == NULL) {
        return NULL;
    }
    map->length = 0;
    map->capacity = INITIAL_CAPACITY;
    map->entries = calloc(map->capacity, sizeof(hm_entry));
    if (map->entries == NULL) {
        free(map);
        return NULL;
    }
    return map;
}

void hm_destroy(hm* map) 
{
    for (size_t i = 0; i < map->capacity; i++) {
        free((void*)map->entries[i].key);
    }   
    free(map->entries);
    free(map);
}

static uint64_t FNV_1A(const char* key) {
    uint64_t hash = FNV_OFFSET;
    for (const char* p = key; *p; p++) {
        hash ^= (uint64_t)(unsigned char)(*p);
        hash *= FNV_PRIME;
    }
    return hash;
}

//wrapper function, in case I use a different one later on
static uint64_t hasher(const char* key) 
{
    return FNV_1A(key);

}



void* hm_get(hm* map, const char* key) 
{
    uint64_t hash = hasher(key);
    size_t index = (size_t) (hash & (uint64_t)(map->capacity - 1));
    size_t index_cpy = index;
    int is_round = 0;
    while (map->entries[index].key != NULL) {
        if (is_round && index == index_cpy) {
            return NULL;
        }
        if (strcmp(key, map->entries[index].key) == 0) {
            return map->entries[index].value;
        } else {
            index++;
            if (index >= map->capacity) {
                is_round = 0;
                index=0;
            }
        }
    }
    return NULL;
}

static const char* hm_set_entry(hm_entry *entries, size_t capacity, const char* key, void* value, size_t* plength) 
{
    uint64_t hash = hasher(key);   
    size_t index = (size_t)(hash & (uint64_t)(capacity-1));


    while (entries[index].key != NULL) {
        if (strcmp(key, entries[index].key) == 0) {
            // found key -> update value
            entries[index].value = value;
            return entries[index].key;
        }
        //move on if not found
        index++;
        //wrap at end
        if (index >= capacity) {
            index =0;
        }
    }

    // if key wasn't found, allocate and copy, then insert
    if (plength != NULL) {
        key = strdup(key);
        if (key == NULL) {
            return NULL;
        }
        (*plength)++;
    }
    entries[index].key = (char*)key;
    entries[index].value = value;
    return key;
}

static int hm_expand(hm* map) 
{
    size_t new_capacity = map->capacity*2;
    if (new_capacity < map->capacity) {
        return 0; //overflow!!!
     }
    hm_entry* new_entries = calloc(new_capacity, sizeof(hm_entry));
    if (new_entries == NULL) {
        return 0;
    }

    for (size_t i = 0; i < map->capacity; i++) {
        hm_entry entry = map->entries[i];
        if (entry.key != NULL) {
            hm_set_entry(new_entries, new_capacity, entry.key, entry.value, NULL);
        }
    }

    free(map->entries);
    map->entries = new_entries;
    map->capacity = new_capacity;
    return 1;
}


const char* hm_set(hm* map, const char* key, void* value) 
{
    if (value == NULL) {
        return NULL;
    }

    if (map->length >= map->capacity) {
        if (!hm_expand(map)) {
            return NULL;
        }
    }

    return hm_set_entry(map->entries, map->capacity, key, value, &map->length); 
}

extern int hm_remove(hm* map, char* key) {
    uint64_t hash = hasher(key);
    size_t index = (size_t) (hash & (uint64_t)(map->capacity - 1));
    size_t index_cpy = index;
    int is_round = 0;
    while (map->entries[index].key != NULL) {
        if (is_round && index == index_cpy) {
            return 0;
        }
        if (strcmp(key, map->entries[index].key) == 0) {
            map->length -= 1;
            map->entries[index].key = NULL;
            return 1;
        } else {
            index++;
            if (index >= map->capacity) {
                is_round = 1;
                index=0;
            }

        }
    }
    return 0;
}

size_t hm_len(hm* map) {
    return map->length;
}

hmi hm_iterator(hm* map) {
    hmi iter;
    iter._map = map;
    iter._index = 0;
    return iter;
}

int hm_iter_next(hmi* iter) {
    hm* map = iter->_map;
    while (iter->_index < map->capacity) {
        size_t i = iter->_index;
        iter->_index++;
        if (map->entries[i].key != NULL) {
            hm_entry entry = map->entries[i];
            iter->key = entry.key;
            iter->value = entry.value;
            return 1;
        }
    }
    return 0;
}


void hm_dump(hm* map, int idx) {
    hmi iter = hm_iterator(map);
    int i = 0;
    while (hm_iter_next(&iter)) {
        if (idx) {
            printf("%d ", i);
        }
        printf("%s: %s\n", iter.key, iter.value);
        i++;
    }
}


int hm_serialize_cstr(hm* map, uint8_t* buffer, int buffer_len, uint8_t kv_delim, uint8_t entry_delim) {
    int offset = 0;
    hmi iter = hm_iterator(map);
    while (hm_iter_next(&iter)) {
        size_t k_len = strlen(iter.key);
        size_t v_len = strlen(iter.value);
        memcpy(buffer+offset, iter.key, k_len);
        offset += k_len;
        buffer[offset] = kv_delim;
        offset += 1;
        memcpy(buffer+offset, (uint8_t*)iter.value, v_len);
        offset += v_len;
        buffer[offset] = entry_delim;
        offset++;
    }
    return offset;
}




#endif //HM_IMPLEMENTATION
