/**
 * @file table_encrypt.c
 * @brief Table-based encryption implementation for UDP proxy packets
 * @author Seed Development Team
 * @date 2025
 */

#include "table_encrypt.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Simple hash function for password-based key derivation */
static uint32_t simple_hash(const char *str)
{
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* Simple base64 encoding table */
static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Simple base64 encoding */
static int simple_base64_encode(const uint8_t *input, int length, char *output)
{
    int i = 0, j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];

    while (length--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                output[j++] = base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(int k = i; k < 3; k++)
            char_array_3[k] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int k = 0; (k < i + 1); k++)
            output[j++] = base64_chars[char_array_4[k]];

        while((i++ < 3))
            output[j++] = '=';
    }
    output[j] = '\0';
    return j;
}

/* Simple base64 decoding */
static int simple_base64_decode(const char *input, uint8_t *output)
{
    int in_len = strlen(input);
    int i = 0, j = 0, in = 0;
    uint8_t char_array_4[4], char_array_3[3];

    while (in_len-- && (input[in] != '=') && 
           ((input[in] >= 'A' && input[in] <= 'Z') || 
            (input[in] >= 'a' && input[in] <= 'z') || 
            (input[in] >= '0' && input[in] <= '9') || 
            (input[in] == '+') || (input[in] == '/'))) {
        
        /* Find character in base64 table */
        for (int k = 0; k < 64; k++) {
            if (base64_chars[k] == input[in]) {
                char_array_4[i++] = k;
                break;
            }
        }
        in++;

        if (i == 4) {
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                output[j++] = char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (int k = i; k <4; k++)
            char_array_4[k] = 0;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (int k = 0; (k < i - 1); k++)
            output[j++] = char_array_3[k];
    }

    return j;
}

/* Static variables */
static bool table_encrypt_initialized = false;

int table_encrypt_init(void)
{
    if (table_encrypt_initialized) {
        return 0;
    }
    
    log_debug("Initializing table encryption module");
    
    /* Seed random number generator */
    srand((unsigned int)time(NULL));
    
    table_encrypt_initialized = true;
    log_info("Table encryption module initialized");
    return 0;
}

void table_encrypt_cleanup(void)
{
    if (!table_encrypt_initialized) {
        return;
    }
    
    log_debug("Cleaning up table encryption module");
    table_encrypt_initialized = false;
}

int table_generate_from_password(const char *password, uint8_t table[TABLE_KEY_SIZE])
{
    if (!password || !table) {
        log_error("Invalid parameters for table generation");
        return -1;
    }
    
    if (!table_encrypt_initialized) {
        log_error("Table encryption module not initialized");
        return -1;
    }
    
    /* Generate simple hash from password for seeding */
    uint32_t hash = simple_hash(password);
    srand(hash);
    
    /* Initialize table with identity mapping */
    for (int i = 0; i < TABLE_KEY_SIZE; i++) {
        table[i] = i;
    }
    
    /* Fisher-Yates shuffle using seeded random */
    for (int i = TABLE_KEY_SIZE - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        uint8_t temp = table[i];
        table[i] = table[j];
        table[j] = temp;
    }
    
    /* Verify table is valid */
    if (!table_validate(table)) {
        log_error("Generated table validation failed");
        return -1;
    }
    
    log_debug("Table encryption generated from password");
    return 0;
}

int table_generate_random(uint8_t table[TABLE_KEY_SIZE])
{
    if (!table) {
        log_error("Invalid table parameter");
        return -1;
    }
    
    if (!table_encrypt_initialized) {
        log_error("Table encryption module not initialized");
        return -1;
    }
    
    /* Initialize table with identity mapping */
    for (int i = 0; i < TABLE_KEY_SIZE; i++) {
        table[i] = i;
    }
    
    /* Fisher-Yates shuffle using standard random */
    for (int i = TABLE_KEY_SIZE - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        uint8_t temp = table[i];
        table[i] = table[j];
        table[j] = temp;
    }
    
    /* Verify table is valid */
    if (!table_validate(table)) {
        log_error("Generated random table validation failed");
        return -1;
    }
    
    log_debug("Random table encryption generated");
    return 0;
}

bool table_validate(const uint8_t table[TABLE_KEY_SIZE])
{
    if (!table) {
        return false;
    }
    
    bool seen[TABLE_KEY_SIZE] = {false};
    
    /* Check that every byte value 0-255 appears exactly once */
    for (int i = 0; i < TABLE_KEY_SIZE; i++) {
        if (seen[table[i]]) {
            log_error("Table validation failed: duplicate value %d", table[i]);
            return false;
        }
        seen[table[i]] = true;
    }
    
    return true;
}

int table_create_inverse(const uint8_t encrypt_table[TABLE_KEY_SIZE], 
                        uint8_t decrypt_table[TABLE_KEY_SIZE])
{
    if (!encrypt_table || !decrypt_table) {
        log_error("Invalid table parameters for inverse creation");
        return -1;
    }
    
    if (!table_validate(encrypt_table)) {
        log_error("Invalid encrypt table for inverse creation");
        return -1;
    }
    
    /* Create inverse mapping */
    for (int i = 0; i < TABLE_KEY_SIZE; i++) {
        decrypt_table[encrypt_table[i]] = i;
    }
    
    /* Verify inverse table is valid */
    if (!table_validate(decrypt_table)) {
        log_error("Generated inverse table validation failed");
        return -1;
    }
    
    log_debug("Inverse table created successfully");
    return 0;
}

int table_context_create(const char *password, struct table_encrypt_context **ctx)
{
    if (!password || !ctx) {
        log_error("Invalid parameters for table context creation");
        return -1;
    }
    
    if (!table_encrypt_initialized) {
        log_error("Table encryption module not initialized");
        return -1;
    }
    
    /* Allocate context */
    struct table_encrypt_context *context = malloc(sizeof(struct table_encrypt_context));
    if (!context) {
        log_error("Failed to allocate table encryption context");
        return -1;
    }
    
    /* Generate encryption table from password */
    if (table_generate_from_password(password, context->encrypt_table) != 0) {
        log_error("Failed to generate encryption table from password");
        free(context);
        return -1;
    }
    
    /* Create decrypt table (inverse of encrypt table) */
    if (table_create_inverse(context->encrypt_table, context->decrypt_table) != 0) {
        log_error("Failed to create decrypt table");
        free(context);
        return -1;
    }
    
    context->initialized = true;
    *ctx = context;
    
    log_debug("Table encryption context created from password");
    return 0;
}

int table_context_create_from_key(const uint8_t key[TABLE_KEY_SIZE], 
                                 struct table_encrypt_context **ctx)
{
    if (!key || !ctx) {
        log_error("Invalid parameters for table context creation from key");
        return -1;
    }
    
    if (!table_encrypt_initialized) {
        log_error("Table encryption module not initialized");
        return -1;
    }
    
    /* Validate input key */
    if (!table_validate(key)) {
        log_error("Invalid encryption key provided");
        return -1;
    }
    
    /* Allocate context */
    struct table_encrypt_context *context = malloc(sizeof(struct table_encrypt_context));
    if (!context) {
        log_error("Failed to allocate table encryption context");
        return -1;
    }
    
    /* Copy encryption table */
    memcpy(context->encrypt_table, key, TABLE_KEY_SIZE);
    
    /* Create decrypt table (inverse of encrypt table) */
    if (table_create_inverse(context->encrypt_table, context->decrypt_table) != 0) {
        log_error("Failed to create decrypt table");
        free(context);
        return -1;
    }
    
    context->initialized = true;
    *ctx = context;
    
    log_debug("Table encryption context created from raw key");
    return 0;
}

void table_context_destroy(struct table_encrypt_context *ctx)
{
    if (!ctx) {
        return;
    }
    
    log_debug("Destroying table encryption context");
    
    /* Clear sensitive data */
    memset(ctx->encrypt_table, 0, TABLE_KEY_SIZE);
    memset(ctx->decrypt_table, 0, TABLE_KEY_SIZE);
    ctx->initialized = false;
    
    free(ctx);
}

int table_encrypt_data(struct table_encrypt_context *ctx, uint8_t *data, size_t len)
{
    if (!ctx || !data || !ctx->initialized) {
        log_error("Invalid parameters for table encryption");
        return -1;
    }
    
    /* Apply encryption table to each byte */
    for (size_t i = 0; i < len; i++) {
        data[i] = ctx->encrypt_table[data[i]];
    }
    
    return 0;
}

int table_decrypt_data(struct table_encrypt_context *ctx, uint8_t *data, size_t len)
{
    if (!ctx || !data || !ctx->initialized) {
        log_error("Invalid parameters for table decryption");
        return -1;
    }
    
    /* Apply decryption table to each byte */
    for (size_t i = 0; i < len; i++) {
        data[i] = ctx->decrypt_table[data[i]];
    }
    
    return 0;
}

int table_encrypt_copy(const struct table_encrypt_context *ctx, 
                      const uint8_t *input, uint8_t *output, size_t len)
{
    if (!ctx || !input || !output || !ctx->initialized) {
        log_error("Invalid parameters for table encryption copy");
        return -1;
    }
    
    /* Apply encryption table to each byte */
    for (size_t i = 0; i < len; i++) {
        output[i] = ctx->encrypt_table[input[i]];
    }
    
    return 0;
}

int table_decrypt_copy(const struct table_encrypt_context *ctx, 
                      const uint8_t *input, uint8_t *output, size_t len)
{
    if (!ctx || !input || !output || !ctx->initialized) {
        log_error("Invalid parameters for table decryption copy");
        return -1;
    }
    
    /* Apply decryption table to each byte */
    for (size_t i = 0; i < len; i++) {
        output[i] = ctx->decrypt_table[input[i]];
    }
    
    return 0;
}

int table_export_base64(const uint8_t table[TABLE_KEY_SIZE], 
                       char *base64, size_t base64_size)
{
    if (!table || !base64 || base64_size < 344) {
        log_error("Invalid parameters for table base64 export");
        return -1;
    }
    
    int encoded_len = simple_base64_encode(table, TABLE_KEY_SIZE, base64);
    if (encoded_len <= 0 || (size_t)encoded_len >= base64_size) {
        log_error("Base64 encoding failed or buffer too small");
        return -1;
    }
    
    log_debug("Table exported to base64");
    return 0;
}

int table_import_base64(const char *base64, uint8_t table[TABLE_KEY_SIZE])
{
    if (!base64 || !table) {
        log_error("Invalid parameters for table base64 import");
        return -1;
    }
    
    int decoded_len = simple_base64_decode(base64, table);
    
    if (decoded_len != TABLE_KEY_SIZE) {
        log_error("Invalid base64 table data length: %d", decoded_len);
        return -1;
    }
    
    /* Validate imported table */
    if (!table_validate(table)) {
        log_error("Imported table validation failed");
        return -1;
    }
    
    log_debug("Table imported from base64");
    return 0;
}