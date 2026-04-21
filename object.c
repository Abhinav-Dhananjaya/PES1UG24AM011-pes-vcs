
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>

/* Convert binary hash to 64-char hex string */
void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++)
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    hex_out[HASH_HEX_SIZE] = '\0';
}

/* Convert 64-char hex string to binary hash */
int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) != HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

/* Build the file path for an object */
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

/* Check if an object exists */
int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    struct stat st;
    return stat(path, &st) == 0;
}

static const char *type_to_str(ObjectType type) {
    switch (type) {
        case OBJ_BLOB:   return "blob";
        case OBJ_TREE:   return "tree";
        case OBJ_COMMIT: return "commit";
        default:         return "unknown";
    }
}

static ObjectType str_to_type(const char *str) {
    if (strcmp(str, "blob")   == 0) return OBJ_BLOB;
    if (strcmp(str, "tree")   == 0) return OBJ_TREE;
    if (strcmp(str, "commit") == 0) return OBJ_COMMIT;
    return -1;
}

/* Write an object to the store */
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = type_to_str(type);

    // Step 1: Build header "type size\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);

    // Step 2: Combine header + \0 + data
    size_t full_len = header_len + 1 + len;
    unsigned char *full = malloc(full_len);
    if (!full) return -1;
    memcpy(full, header, header_len);
    full[header_len] = '\0';
    memcpy(full + header_len + 1, data, len);

    // Step 3: SHA-256 hash
    unsigned char hash[HASH_SIZE];
    SHA256(full, full_len, hash);
    memcpy(id_out->hash, hash, HASH_SIZE);

    // Step 4: Build path
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char dir_path[512], obj_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/%.2s", OBJECTS_DIR, hex);
    snprintf(obj_path, sizeof(obj_path), "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);

    // Deduplication
    struct stat st;
    if (stat(obj_path, &st) == 0) {
        free(full);
        return 0;
    }

    // Create shard directory
    mkdir(dir_path, 0755);

    // Step 5: Atomic write - temp file then rename
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_XXXXXX", OBJECTS_DIR);
    int fd = mkstemp(tmp_path);
    if (fd < 0) { free(full); return -1; }

    ssize_t w = write(fd, full, full_len);
    (void)w;
    fsync(fd);
    close(fd);
    free(full);

    rename(tmp_path, obj_path);
    return 0;
}

/* Read an object from the store */
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Step 1: Build path
    char obj_path[512];
    object_path(id, obj_path, sizeof(obj_path));

    // Step 2: Read file
    int fd = open(obj_path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    fstat(fd, &st);
    size_t file_size = st.st_size;

    unsigned char *buffer = malloc(file_size);
    if (!buffer) { close(fd); return -1; }

    ssize_t r = read(fd, buffer, file_size);
    (void)r;
    close(fd);

    // Step 3: Verify hash
    unsigned char hash[HASH_SIZE];
    SHA256(buffer, file_size, hash);
    if (memcmp(hash, id->hash, HASH_SIZE) != 0) {
        free(buffer);
        return -1;  // Corrupted!
    }

    // Step 4: Parse header - find \0 separator
    unsigned char *null_pos = memchr(buffer, '\0', file_size);
    if (!null_pos) { free(buffer); return -1; }

    char type_str[16];
    size_t size;
    sscanf((char *)buffer, "%15s %zu", type_str, &size);

    // Step 5: Return data
    *type_out = str_to_type(type_str);
    *len_out  = size;
    *data_out = malloc(size);
    memcpy(*data_out, null_pos + 1, size);

    free(buffer);
    return 0;
}
