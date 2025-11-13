#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <openssl/evp.h> // Used for AES-GCM and now modern Hashing
#include <openssl/rand.h>
#include <inttypes.h>
#include <time.h>
#include <strings.h>

#define TARGET_CHUNKS 3 // NEW: Always chunk into exactly 3 parts
#define KEYS_DIR "./keys"
#define OUTPUT_DIR "./files" // CHANGED: Output directory is now ./files
#define KEY_SIZE 32 // 256 bits
#define NONCE_SIZE 12 // 96 bits
#define TAG_SIZE 16

#define DEBUG_HASHES 1 // Flag to enable hash comparison print statements

// --- utilities ---
static void hex_encode(const uint8_t *in, size_t inlen, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < inlen; ++i) {
        out[i*2] = hex[(in[i] >> 4) & 0xF];
        out[i*2+1] = hex[in[i] & 0xF];
    }
    out[inlen*2] = '\0';
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        errno = ENOTDIR;
        return -1;
    }
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static unsigned char *read_file_all(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long size = ftell(f);
    if (size < 0) { fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = malloc(size);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, size, f);
    fclose(f);
    if (r != (size_t)size) { free(buf); return NULL; }
    *out_len = (size_t)size;
    return buf;
}

// --- crypto AES-GCM encrypt/decrypt ---
static int aes_gcm_encrypt(const uint8_t *key, const uint8_t *nonce,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t **ciphertext_out, size_t *cipher_len_out)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *ciphertext = NULL;
    int len = 0, ciphertext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto end;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL)) goto end;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) goto end;

    ciphertext = malloc(plaintext_len + TAG_SIZE);
    if (!ciphertext) goto end;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len)) goto end;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto end;
    ciphertext_len += len;

    // get tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, ciphertext + ciphertext_len)) goto end;
    ciphertext_len += TAG_SIZE;

    *ciphertext_out = ciphertext;
    *cipher_len_out = (size_t)ciphertext_len;
    ret = 1;

end:
    if (!ret && ciphertext) { free(ciphertext); ciphertext = NULL; }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int aes_gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                           const uint8_t *ciphertext, size_t cipher_len,
                           uint8_t **plaintext_out, size_t *plaintext_len_out)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *plaintext = NULL;
    int len = 0, plaintext_len = 0;
    if (cipher_len < TAG_SIZE) return 0;
    size_t data_len = cipher_len - TAG_SIZE;
    const uint8_t *tag = ciphertext + data_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto end;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, NULL)) goto end;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) goto end;

    plaintext = malloc(data_len);
    if (!plaintext) goto end;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)data_len)) goto end;
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag)) goto end;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        // authentication failed
        goto end;
    }
    plaintext_len += len;

    *plaintext_out = plaintext;
    *plaintext_len_out = (size_t)plaintext_len;
    ret = 1;

end:
    if (!ret && plaintext) { free(plaintext); plaintext = NULL; }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// --- hashing helpers (Updated to use modern EVP_Digest API) ---
static void sha256_hex(const uint8_t *data, size_t data_len, char *hex_out /* 65 bytes */) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *mdctx = NULL;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) return; 

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) goto end;
    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) goto end;
    if (1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len)) goto end;

    hex_encode(digest, digest_len, hex_out);

end:
    if (mdctx) EVP_MD_CTX_free(mdctx);
}

// --- chunking and metadata ---
typedef struct {
    char chunk_id[33]; // first 16 bytes hex -> 32 chars + \0
    char file_path[512];
    size_t size;
    int index;
    char hash[65];
} chunk_meta_t;

static int write_chunks_and_metadata(const char *file_name,
                                     const uint8_t *ciphertext, size_t cipher_len,
                                     const uint8_t *key, const uint8_t *nonce,
                                     char *file_id_hex_out)
{
    // compute file_id (sha256 of ciphertext) and take first 16 hex chars
    char file_hash_hex[65];
    sha256_hex(ciphertext, cipher_len, file_hash_hex);

    // --- CORRECTION : Ces deux lignes manquaient ! ---
    // Copier les 16 premiers caractères hexadécimaux dans le tampon de sortie
    strncpy(file_id_hex_out, file_hash_hex, 16);
    file_id_hex_out[16] = '\0';
    // --- Fin de la correction ---

    if (ensure_dir(OUTPUT_DIR) != 0) { 
        // FIX: Update perror message to reflect the new directory name if needed, though "output" is generic.
        // We can just let perror print the path.
        perror("ensure_dir(OUTPUT_DIR)"); 
        return -1; 
    }
    if (ensure_dir(KEYS_DIR) != 0) { perror("ensure_dir(KEYS_DIR)"); return -1; }

    // --- NEW CHUNKING LOGIC: Exactly 3 equal parts ---
    const size_t num_chunks = TARGET_CHUNKS;
    const size_t base_chunk_size = cipher_len / num_chunks;
    const size_t remainder = cipher_len % num_chunks;

    // Allocate metadata structure for exactly 3 chunks
    chunk_meta_t *metas = calloc(num_chunks, sizeof(chunk_meta_t));
    if (!metas) return -1;

    size_t current_offset = 0;
    size_t actual_chunks_written = 0;

    for (size_t i = 0; i < num_chunks; ++i) {
        size_t this_len = base_chunk_size;
        
        if (i < remainder) {
            this_len++;
        }
        
        if (this_len == 0 && cipher_len > 0) {
             continue; 
        } else if (this_len == 0 && cipher_len == 0) {
            continue;
        }

        size_t start = current_offset;

        // compute chunk hash
        char chunk_hash[65];
        sha256_hex(ciphertext + start, this_len, chunk_hash);
        
#if DEBUG_HASHES
        fprintf(stderr, "[DEBUG ENCRYPT] Chunk %04zu Hash (MEM): %s\n", i, chunk_hash);
#endif

        char chunk_id[33];
        strncpy(chunk_id, chunk_hash, 16);
        chunk_id[16] = '\0';

        char filename[512];
        snprintf(filename, sizeof(filename), "%s/%s_chunk_%04zu.enc", OUTPUT_DIR, file_id_hex_out, i);

        FILE *f = fopen(filename, "wb");
        if (!f) { perror("write chunk (fopen)"); free(metas); return -1; }
        if (fwrite(ciphertext + start, 1, this_len, f) != this_len) { 
            perror("write chunk (fwrite)"); 
            fclose(f); 
            free(metas); 
            return -1; 
        }

        // --- I/O synchronization (fflush and fsync) for robustness ---
        if (fflush(f) != 0) {
             perror("write chunk (fflush)");
             fclose(f);
             free(metas);
             return -1;
        }
        if (fsync(fileno(f)) != 0) {
            perror("write chunk (fsync)");
            fclose(f);
            free(metas);
            return -1;
        }
        
        if (fclose(f) != 0) { 
            perror("write chunk (fclose)"); 
            free(metas); 
            return -1; 
        }
        // --- End I/O sync ---

        // Store metadata for the chunk we just successfully wrote
        snprintf(metas[actual_chunks_written].chunk_id, sizeof(metas[actual_chunks_written].chunk_id), "%s", chunk_id);
        snprintf(metas[actual_chunks_written].file_path, sizeof(metas[actual_chunks_written].file_path), "%s", filename);
        metas[actual_chunks_written].size = this_len;
        metas[actual_chunks_written].index = (int)i; 
        snprintf(metas[actual_chunks_written].hash, sizeof(metas[actual_chunks_written].hash), "%s", chunk_hash);
        
        current_offset += this_len;
        actual_chunks_written++; 
    }

    // write metadata JSON
    char key_hex[KEY_SIZE*2 + 1];
    char nonce_hex[NONCE_SIZE*2 + 1];
    hex_encode(key, KEY_SIZE, key_hex);
    hex_encode(nonce, NONCE_SIZE, nonce_hex);

    // compute original name from file_name
    const char *basename = strrchr(file_name, '/');
    basename = basename ? basename + 1 : file_name;

    // JSON: simple manual formatting
    char metadata_path[512];
    snprintf(metadata_path, sizeof(metadata_path), "%s/%s.json", KEYS_DIR, file_id_hex_out);

    FILE *mf = fopen(metadata_path, "w");
    if (!mf) { perror("write metadata"); free(metas); return -1; }

    time_t now = time(NULL);

    fprintf(mf, "{\n");
    fprintf(mf, "  \"file_id\": \"%s\",\n", file_id_hex_out);
    fprintf(mf, "  \"original_name\": \"%s\",\n", basename);
    fprintf(mf, "  \"original_size\": %zu,\n", (size_t)0); 
    fprintf(mf, "  \"encrypted_size\": %zu,\n", cipher_len);
    fprintf(mf, "  \"encryption\": {\n");
    fprintf(mf, "    \"algorithm\": \"AES-256-GCM\",\n");
    fprintf(mf, "    \"key\": \"%s\",\n", key_hex);
    fprintf(mf, "    \"nonce\": \"%s\"\n", nonce_hex);
    fprintf(mf, "  },\n");
    fprintf(mf, "  \"chunks\": [\n");
    
    // Iterate over actual chunks and write JSON fields in an order friendly to naive parsing.
    for (size_t i = 0; i < actual_chunks_written; ++i) {
        fprintf(mf, "    {\n");
        // NEW ORDER: Place file_path first so the naive parser can find all other fields after it
        fprintf(mf, "      \"file_path\": \"%s\",\n", metas[i].file_path); 
        fprintf(mf, "      \"chunk_id\": \"%s\",\n", metas[i].chunk_id);
        fprintf(mf, "      \"hash\": \"%s\",\n", metas[i].hash);
        fprintf(mf, "      \"size\": %zu,\n", metas[i].size);
        fprintf(mf, "      \"index\": %d\n", metas[i].index); // Last field (no comma)
        fprintf(mf, "    }%s\n", (i+1 < actual_chunks_written)? ",": ""); 
    }
    fprintf(mf, "  ],\n");
    fprintf(mf, "  \"created_at\": %ld\n", (long)now);
    fprintf(mf, "}\n");
    
    // Ensure metadata file is fully written and closed
    if (fflush(mf) != 0 || fsync(fileno(mf)) != 0 || fclose(mf) != 0) {
        perror("write metadata (sync/close)"); 
        free(metas); 
        return -1; 
    }

    free(metas);
    return 0;
}

// --- reassemble chunks from metadata file (simple parser) ---
typedef struct {
    char file_path[512];
    int index;
    char hash[65];
    size_t size;
} loaded_chunk_t;

static loaded_chunk_t *load_metadata_chunks(const char *metadata_file, size_t *out_num) {
    // naive parser: find occurrences of "file_path": "..." and "index": N and "hash": "..." and "size": n
    FILE *f = fopen(metadata_file, "r");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    buf[sz] = '\0';
    fclose(f);

    // count occurrences of "file_path"
    size_t count = 0;
    char *p = buf;
    while ((p = strstr(p, "\"file_path\"")) != NULL) { count++; p += 10; }
    if (count == 0) { free(buf); return NULL; }

    loaded_chunk_t *chunks = calloc(count, sizeof(loaded_chunk_t));
    if (!chunks) { free(buf); return NULL; }

    size_t idx = 0;
    char *cursor = buf;
    while ((cursor = strstr(cursor, "\"file_path\"")) != NULL && idx < count) {
        char *start = strchr(cursor, ':');
        if (!start) break;
        start++;
        while (*start && (*start==' '||*start=='\t')) start++;
        if (*start == '\"') start++;
        char *end = strchr(start, '\"');
        if (!end) break;
        size_t len = end - start;
        if (len >= sizeof(chunks[idx].file_path)) len = sizeof(chunks[idx].file_path)-1;
        strncpy(chunks[idx].file_path, start, len);
        chunks[idx].file_path[len] = '\0';

        // NOTE: The parser continues searching *forward* from 'end' (the end quote of file_path).
        // Since file_path is now the *first* field, this search will correctly find the remaining fields
        // within the current JSON object, which is what caused the previous bug.

        // find index
        char *ix = strstr(end, "\"index\"");
        if (ix) {
            char *col = strchr(ix, ':');
            if (col) {
                long v = strtol(col+1, NULL, 10);
                chunks[idx].index = (int)v;
            }
        }

        // find size
        char *szs = strstr(end, "\"size\"");
        if (szs) {
            char *col = strchr(szs, ':');
            if (col) {
                long v = strtol(col+1, NULL, 10);
                chunks[idx].size = (size_t)v;
            }
        }

        // find hash
        char *hs = strstr(end, "\"hash\"");
        if (hs) {
            char *col = strchr(hs, ':');
            if (col) {
                char *hstart = strchr(col, '\"');
                if (hstart) {
                    hstart++;
                    char *hend = strchr(hstart, '\"');
                    if (hend) {
                        size_t hlen = hend - hstart;
                        if (hlen >= sizeof(chunks[idx].hash)) hlen = sizeof(chunks[idx].hash)-1;
                        strncpy(chunks[idx].hash, hstart, hlen);
                        chunks[idx].hash[hlen] = '\0';
                    }
                }
            }
        }

        idx++;
        // Move cursor past the end of the current object's block to start searching for the next "file_path"
        cursor = end;
    }

    free(buf);
    *out_num = idx;
    return chunks;
}

// Hashing function for file content using modern EVP API
static int verify_chunk_hash(const char *path, const char *expected_hex) {
    int ret = 0;
    FILE *f = fopen(path, "rb");
    if (!f) { perror("open chunk"); return 0; }
    
    EVP_MD_CTX *mdctx = NULL;
    
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) goto end;

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) goto end;
    
    unsigned char buf[8192];
    size_t r;
    while ((r = fread(buf,1,sizeof(buf),f)) > 0) {
        if (1 != EVP_DigestUpdate(mdctx, buf, r)) goto end;
    }
    
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    if (1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len)) goto end;
    
    char hex[65];
    hex_encode(digest, digest_len, hex);
    
#if DEBUG_HASHES
    fprintf(stderr, "[DEBUG DECRYPT] Verifying %s...\n", path);
    fprintf(stderr, "[DEBUG DECRYPT] Expected Hash (META): %s\n", expected_hex);
    fprintf(stderr, "[DEBUG DECRYPT] Computed Hash (FILE): %s\n", hex);
#endif

    ret = (strcasecmp(hex, expected_hex) == 0);

end:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    // Note: Do not check fclose result here, as we are only reading.
    fclose(f); 
    return ret;
}

static int reassemble_chunks_to_buffer(loaded_chunk_t *chunks, size_t num_chunks, uint8_t **out_buf, size_t *out_len) {
    // sort by index (simple bubble for small counts)
    for (size_t i=0;i<num_chunks;i++){
        for (size_t j=i+1;j<num_chunks;j++){
            if (chunks[j].index < chunks[i].index){
                loaded_chunk_t tmp = chunks[i]; chunks[i]=chunks[j]; chunks[j]=tmp;
            }
        }
    }
    // calculate total size
    size_t total = 0;
    for (size_t i=0;i<num_chunks;i++) total += chunks[i].size;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;
    size_t pos = 0;
    for (size_t i=0;i<num_chunks;i++) {
        FILE *f = fopen(chunks[i].file_path, "rb");
        if (!f) { free(buf); return -1; }
        size_t r = fread(buf+pos,1,chunks[i].size,f);
        fclose(f);
        if (r != chunks[i].size) { free(buf); return -1; }
        pos += r;
    }
    *out_buf = buf;
    *out_len = total;
    return 0;
}

// --- main operations ---
static int cmd_encrypt(const char *path) {
    size_t plain_len;
    unsigned char *plaintext = read_file_all(path, &plain_len);
    if (!plaintext) { fprintf(stderr, "Cannot read file %s\n", path); return 1; }

    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    if (1 != RAND_bytes(key, KEY_SIZE)) { fprintf(stderr, "RAND_bytes key failed\n"); free(plaintext); return 1; }
    if (1 != RAND_bytes(nonce, NONCE_SIZE)) { fprintf(stderr, "RAND_bytes nonce failed\n"); free(plaintext); return 1; }

    uint8_t *ciphertext = NULL;
    size_t cipher_len = 0;
    if (!aes_gcm_encrypt(key, nonce, plaintext, plain_len, &ciphertext, &cipher_len)) {
        fprintf(stderr, "Encryption failed\n");
        free(plaintext);
        return 1;
    }

    char file_id[17];
    if (write_chunks_and_metadata(path, ciphertext, cipher_len, key, nonce, file_id) != 0) {
        fprintf(stderr, "Failed to write chunks/metadata\n");
        free(plaintext);
        free(ciphertext);
        return 1;
    }

    printf("✅ Encrypted: file_id=%s, chunks_dir=%s, metadata=%s/%s.json\n", file_id, OUTPUT_DIR, KEYS_DIR, file_id);

    free(plaintext);
    free(ciphertext);
    return 0;
}

static int cmd_decrypt(const char *file_id, const char *output_path) {
    char metadata_path[512];
    snprintf(metadata_path, sizeof(metadata_path), "%s/%s.json", KEYS_DIR, file_id);

    // load metadata chunks
    size_t num_chunks = 0;
    loaded_chunk_t *chunks = load_metadata_chunks(metadata_path, &num_chunks);
    if (!chunks) { fprintf(stderr, "Failed to parse metadata or no chunks found\n"); return 1; }

    // verify each chunk hash
    for (size_t i=0;i<num_chunks;i++) {
        if (!verify_chunk_hash(chunks[i].file_path, chunks[i].hash)) {
            fprintf(stderr, "Chunk hash mismatch for %s\n", chunks[i].file_path);
            free(chunks);
            return 1;
        }
    }

    // reassemble
    uint8_t *ciphertext = NULL;
    size_t cipher_len = 0;
    if (reassemble_chunks_to_buffer(chunks, num_chunks, &ciphertext, &cipher_len) != 0) {
        fprintf(stderr, "Failed to reassemble chunks\n");
        free(chunks);
        return 1;
    }

    // verify file_id
    char full_hash[65];
    sha256_hex(ciphertext, cipher_len, full_hash);
    if (strncmp(full_hash, file_id, 16) != 0) {
        fprintf(stderr, "Integrity check failed: computed id %.16s != expected %s\n", full_hash, file_id);
        free(chunks);
        free(ciphertext);
        return 1;
    }

    // parse key & nonce from metadata file (naive)
    FILE *mf = fopen(metadata_path, "r");
    if (!mf) { perror("open metadata"); free(chunks); free(ciphertext); return 1; }
    fseek(mf, 0, SEEK_END);
    long msz = ftell(mf);
    rewind(mf);
    char *mbuf = malloc(msz+1);
    if (fread(mbuf,1,msz,mf) != (size_t)msz) { 
        free(mbuf); fclose(mf); free(chunks); free(ciphertext); 
        fprintf(stderr, "Failed to read full metadata file.\n"); return 1; 
    }
    mbuf[msz] = '\0';
    fclose(mf);

    // --- NOUVEAU : Parser "original_name" ---
    char parsed_original_name[512] = "decrypted_output"; // Nom par défaut si non trouvé
    char *on_pos = strstr(mbuf, "\"original_name\"");
    if (on_pos) {
        char *onq = strchr(on_pos, '\"'); // 1er "
        if (onq) onq = strchr(onq + 1, '\"'); // 2e "
        if (onq) onq = strchr(onq + 1, '\"'); // 3e " (début de la valeur)
        if (onq) {
            char *on_start = onq + 1;
            char *on_end = strchr(on_start, '\"'); // 4e " (fin de la valeur)
            if (on_end) {
                size_t on_len = on_end - on_start;
                if (on_len < sizeof(parsed_original_name) - 1) { // Laisse place pour \0
                    strncpy(parsed_original_name, on_start, on_len);
                    parsed_original_name[on_len] = '\0';
                }
            }
        }
    }
    // --- FIN NOUVEAU ---

    // find "key": "...." and "nonce": "...."
    char *kpos = strstr(mbuf, "\"key\"");
    char *npos = strstr(mbuf, "\"nonce\"");
    if (!kpos || !npos) { fprintf(stderr, "Metadata missing key/nonce\n"); free(mbuf); free(chunks); free(ciphertext); return 1; }
    char *kq = strchr(kpos, '\"');
    if (!kq) { free(mbuf); free(chunks); free(ciphertext); return 1; }
    kq = strchr(kq+1, '\"');
    kq = strchr(kq+1, '\"');
    if (!kq) { free(mbuf); free(chunks); free(ciphertext); return 1; }
    char *kstart = kq+1;
    char *kend = strchr(kstart, '\"');
    if (!kend) { free(mbuf); free(chunks); free(ciphertext); return 1; }
    size_t klen = kend - kstart;
    char *key_hex = malloc(klen+1);
    strncpy(key_hex, kstart, klen);
    key_hex[klen] = '\0';

    char *nq = strchr(npos, '\"');
    nq = strchr(nq+1, '\"');
    nq = strchr(nq+1, '\"');
    char *nstart = nq+1;
    char *nend = strchr(nstart, '\"');
    size_t nlen = nend - nstart;
    char *nonce_hex = malloc(nlen+1);
    strncpy(nonce_hex, nstart, nlen);
    nonce_hex[nlen] = '\0';

    // hex -> bytes
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    for (size_t i=0;i<KEY_SIZE;i++){
        sscanf(&key_hex[i*2], "%2hhx", &key[i]);
    }
    for (size_t i=0;i<NONCE_SIZE;i++){
        sscanf(&nonce_hex[i*2], "%2hhx", &nonce[i]);
    }

    free(key_hex);
    free(nonce_hex);
    free(mbuf);
    free(chunks);

    // decrypt
    uint8_t *plaintext = NULL;
    size_t plain_len = 0;
    if (!aes_gcm_decrypt(key, nonce, ciphertext, cipher_len, &plaintext, &plain_len)) {
        fprintf(stderr, "Decryption failed (auth check)\n");
        free(ciphertext);
        return 1;
    }

    // write output
    // --- LOGIQUE DE SORTIE AMÉLIORÉE ---
    char final_out_path[1024];
    const char *outpath_to_use;

    if (output_path == NULL) {
        // 1. Aucun chemin fourni : utilise le nom original dans le dossier actuel
        outpath_to_use = parsed_original_name;
    } else {
        struct stat st;
        int is_directory = 0;
        // Vérifie si le chemin existe ET est un dossier
        if (stat(output_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            is_directory = 1;
        }

        if (is_directory) {
            // 2. Chemin est un dossier : combine chemin + nom original
            // Gère le cas où le dossier est "./" pour éviter "././filename" (bien que non critique)
            if (strcmp(output_path, "./") == 0) {
                 snprintf(final_out_path, sizeof(final_out_path), "%s", parsed_original_name);
            } else {
                 snprintf(final_out_path, sizeof(final_out_path), "%s/%s", output_path, parsed_original_name);
            }
            outpath_to_use = final_out_path;
        } else {
            // 3. Chemin est un nom de fichier : utilise le nom fourni
            outpath_to_use = output_path;
        }
    }
    // --- FIN LOGIQUE AMÉLIORÉE ---

    // const char *outpath = output_path ? output_path : "./decrypted_output"; // ANCIENNE LOGIQUE
    FILE *of = fopen(outpath_to_use, "wb");
    if (!of) { perror("open output"); free(ciphertext); free(plaintext); return 1; }
    if (fwrite(plaintext, 1, plain_len, of) != plain_len) { perror("fwrite"); fclose(of); free(ciphertext); free(plaintext); return 1; }
    fclose(of);

    printf("✅ Decrypted to %s (size=%zu bytes)\n", outpath_to_use, plain_len);

    free(ciphertext);
    free(plaintext);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage:\n  %s encrypt <file>\n  %s decrypt <file_id> [output_path]\n", argv[0], argv[0]);
        return 1;
    }

    // OpenSSL_add_all_algorithms(); // Not needed for EVP functions

    const char *cmd = argv[1];
    if (strcmp(cmd, "encrypt") == 0) {
        return cmd_encrypt(argv[2]);
    } else if (strcmp(cmd, "decrypt") == 0) {
        const char *out = NULL;
        if (argc >= 4) out = argv[3];
        return cmd_decrypt(argv[2], out);
    } else {
        fprintf(stderr, "Unknown cmd: %s\n", cmd);
        return 1;
    }
}