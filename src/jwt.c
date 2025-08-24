/**
 * @file jwt.c
 * @brief JWT token generation and validation implementation
 * @author Seed Development Team
 * @date 2025
 */

#include "jwt.h"
#include "log.h"
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

/** Secret key for HMAC (in production, this should be configurable) */
static const char *jwt_secret = "seed_reverse_proxy_secret_key_2025";

/**
 * @brief Base64 URL encode
 *
 * @param[in]  input      Input data
 * @param[in]  input_len  Input length
 * @param[out] output     Output buffer
 * @param[in]  output_len Output buffer length
 *
 * @return Length of encoded data, or -1 on error
 */
static int base64url_encode(const unsigned char *input, size_t input_len, 
                            char *output, size_t output_len)
{
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    size_t i, j;
    size_t encoded_len = ((input_len + 2) / 3) * 4;
    
    if (output_len < encoded_len + 1) {
        return -1;
    }
    
    for (i = 0, j = 0; i < input_len;) {
        uint32_t octet_a = i < input_len ? input[i++] : 0;
        uint32_t octet_b = i < input_len ? input[i++] : 0;
        uint32_t octet_c = i < input_len ? input[i++] : 0;
        
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = base64_chars[(triple >> 6) & 0x3F];
        output[j++] = base64_chars[triple & 0x3F];
    }
    
    /* Remove padding for URL-safe base64 */
    while (j > 0 && output[j - 1] == '=') {
        j--;
    }
    
    output[j] = '\0';
    return (int)j;
}

/**
 * @brief Base64 URL decode
 *
 * @param[in]  input       Input base64 string
 * @param[out] output      Output buffer
 * @param[in]  output_len  Output buffer size
 *
 * @return Length of decoded data, or -1 on error
 */
static int base64url_decode(const char *input, unsigned char *output, size_t output_len)
{
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    size_t input_len = strlen(input);
    if (input_len == 0) {
        return 0;
    }
    
    /* Calculate expected output length */
    size_t expected_len = (input_len * 3) / 4;
    if (expected_len >= output_len) {
        return -1;
    }
    
    size_t i, j = 0;
    uint32_t triple = 0;
    int pad_count = 0;
    
    for (i = 0; i < input_len; i += 4) {
        triple = 0;
        
        for (int k = 0; k < 4 && i + k < input_len; k++) {
            char c = input[i + k];
            int val = -1;
            
            /* Find character in base64 alphabet */
            for (int l = 0; l < 64; l++) {
                if (base64_chars[l] == c) {
                    val = l;
                    break;
                }
            }
            
            if (val == -1) {
                if (c == '=') {
                    pad_count++;
                    val = 0; /* Treat padding as 0 */
                } else {
                    return -1; /* Invalid character */
                }
            }
            
            triple |= (val << (18 - k * 6));
        }
        
        /* Extract bytes from triple */
        if (j < output_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < output_len && i + 1 < input_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < output_len && i + 2 < input_len) output[j++] = triple & 0xFF;
    }
    
    /* Adjust for padding */
    j -= pad_count;
    
    return (int)j;
}

/**
 * @brief Hash password using SHA256
 *
 * @param[in]  password     The password to hash
 * @param[out] hash         Buffer to store the hash (32 bytes)
 * @param[out] hash_hex     Buffer to store hex string (65 bytes including null)
 *
 * @return 0 on success, negative error code on failure
 */
int jwt_hash_password(const char *password, unsigned char *hash, char *hash_hex)
{
    if (!password || !hash || !hash_hex) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 32;
    int result = SEED_ERROR;
    
    /* Acquire cryptographic context */
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        log_error("Failed to acquire cryptographic context");
        return SEED_ERROR;
    }
    
    /* Create SHA256 hash object */
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        log_error("Failed to create hash object");
        goto cleanup;
    }
    
    /* Hash the password */
    if (!CryptHashData(hHash, (BYTE*)password, (DWORD)strlen(password), 0)) {
        log_error("Failed to hash data");
        goto cleanup;
    }
    
    /* Get the hash value */
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        log_error("Failed to get hash value");
        goto cleanup;
    }
    
    /* Convert to hex string */
    for (int i = 0; i < 32; i++) {
        sprintf(hash_hex + (i * 2), "%02x", hash[i]);
    }
    hash_hex[64] = '\0';
    
    result = SEED_OK;
    
cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return result;
    
#else
    /* Use OpenSSL for Unix/Linux */
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;
    
    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    
    if (!mdctx) {
        log_error("Failed to create EVP context");
        return SEED_ERROR;
    }
    
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return SEED_ERROR;
    }
    
    if (EVP_DigestUpdate(mdctx, password, strlen(password)) != 1) {
        EVP_MD_CTX_free(mdctx);
        return SEED_ERROR;
    }
    
    if (EVP_DigestFinal_ex(mdctx, hash, &md_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return SEED_ERROR;
    }
    
    EVP_MD_CTX_free(mdctx);
    
    /* Convert to hex string */
    for (unsigned int i = 0; i < md_len; i++) {
        sprintf(hash_hex + (i * 2), "%02x", hash[i]);
    }
    hash_hex[md_len * 2] = '\0';
    
    return SEED_OK;
#endif
}

/**
 * @brief Generate JWT token from password
 *
 * @param[in]  password  The password to hash
 * @param[out] token     Buffer to store the generated token
 * @param[in]  token_len Maximum length of token buffer
 *
 * @return 0 on success, negative error code on failure
 */
int jwt_generate(const char *password, char *token, size_t token_len)
{
    unsigned char hash[32];
    char hash_hex[65];
    char header[256];
    char payload[256];
    char header_b64[512];
    char payload_b64[512];
    char signature_input[1024];
    unsigned char signature[32];
    char signature_b64[512];
    time_t now;
    
    if (!password || !token || token_len < MAX_JWT_LENGTH) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Hash the password */
    if (jwt_hash_password(password, hash, hash_hex) != SEED_OK) {
        return SEED_ERROR;
    }
    
    /* Create JWT header */
    snprintf(header, sizeof(header), "{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    
    /* Create JWT payload with password hash and timestamp */
    time(&now);
    snprintf(payload, sizeof(payload), 
             "{\"sub\":\"%s\",\"iat\":%ld,\"exp\":%ld}", 
             hash_hex, (long)now, (long)(now + 86400)); /* 24 hour expiry */
    
    /* Base64 URL encode header and payload */
    if (base64url_encode((unsigned char *)header, strlen(header), 
                        header_b64, sizeof(header_b64)) < 0) {
        return SEED_ERROR;
    }
    
    if (base64url_encode((unsigned char *)payload, strlen(payload), 
                        payload_b64, sizeof(payload_b64)) < 0) {
        return SEED_ERROR;
    }
    
    /* Create signature input */
    snprintf(signature_input, sizeof(signature_input), "%s.%s", 
             header_b64, payload_b64);
    
#ifdef _WIN32
    /* Use Windows CryptoAPI for HMAC */
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    struct {
        BLOBHEADER header;
        DWORD keySize;
        BYTE keyData[256];
    } keyBlob;
    DWORD sigLen = 32;
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return SEED_ERROR;
    }
    
    /* Create key blob */
    keyBlob.header.bType = PLAINTEXTKEYBLOB;
    keyBlob.header.bVersion = CUR_BLOB_VERSION;
    keyBlob.header.reserved = 0;
    keyBlob.header.aiKeyAlg = CALG_RC2;
    keyBlob.keySize = (DWORD)strlen(jwt_secret);
    memcpy(keyBlob.keyData, jwt_secret, keyBlob.keySize);
    
    /* Import key */
    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, 
                       sizeof(BLOBHEADER) + sizeof(DWORD) + keyBlob.keySize,
                       0, CRYPT_IPSEC_HMAC_KEY, &hKey)) {
        CryptReleaseContext(hProv, 0);
        return SEED_ERROR;
    }
    
    /* Create HMAC */
    if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return SEED_ERROR;
    }
    
    /* Set HMAC algorithm to SHA256 */
    HMAC_INFO hmacInfo = {0};
    hmacInfo.HashAlgid = CALG_SHA_256;
    if (!CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0)) {
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return SEED_ERROR;
    }
    
    /* Hash the data */
    if (!CryptHashData(hHash, (BYTE*)signature_input, (DWORD)strlen(signature_input), 0)) {
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return SEED_ERROR;
    }
    
    /* Get the HMAC */
    if (!CryptGetHashParam(hHash, HP_HASHVAL, signature, &sigLen, 0)) {
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return SEED_ERROR;
    }
    
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
#else
    /* Use OpenSSL for HMAC */
    unsigned int sig_len;
    HMAC(EVP_sha256(), jwt_secret, strlen(jwt_secret),
         (unsigned char *)signature_input, strlen(signature_input),
         signature, &sig_len);
#endif
    
    /* Base64 URL encode signature */
    if (base64url_encode(signature, 32, signature_b64, sizeof(signature_b64)) < 0) {
        return SEED_ERROR;
    }
    
    /* Construct final JWT token */
    snprintf(token, token_len, "%s.%s.%s", header_b64, payload_b64, signature_b64);
    
    return SEED_OK;
}

/* Forward declarations */
static int jwt_extract_password_hash(const char *password, char *hash_out);
static int jwt_extract_hash_from_token(const char *token, char *hash_out);

/**
 * @brief Verify password against JWT token
 *
 * @param[in] password  The password to verify
 * @param[in] token     The JWT token to verify against
 *
 * @return 0 if match, negative error code if no match or error
 */
int jwt_verify(const char *password, const char *token)
{
    char generated_token[MAX_JWT_LENGTH];
    
    if (!password || !token) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Generate token from password */
    if (jwt_generate(password, generated_token, sizeof(generated_token)) != SEED_OK) {
        return SEED_ERROR;
    }
    
    log_debug("JWT verify: password='%s'", password);
    log_debug("JWT verify: stored_token='%s'", token);
    log_debug("JWT verify: generated_token='%s'", generated_token);
    
    /* Extract password hash from generated token */
    char generated_hash[65];
    if (jwt_extract_password_hash(password, generated_hash) != SEED_OK) {
        log_debug("JWT verify: Failed to generate hash for password");
        return SEED_ERROR;
    }
    
    /* Extract password hash from stored token by decoding payload */
    char stored_hash[65];
    if (jwt_extract_hash_from_token(token, stored_hash) != SEED_OK) {
        log_debug("JWT verify: Failed to extract hash from stored token");
        return SEED_ERROR;
    }
    
    log_debug("JWT verify: generated_hash='%s'", generated_hash);
    log_debug("JWT verify: stored_hash='%s'", stored_hash);
    
    /* Compare password hashes directly */
    if (strcmp(generated_hash, stored_hash) == 0) {
        log_debug("JWT verify: Password hashes match - authentication successful");
        return SEED_OK;
    }
    
    log_debug("JWT verify: Password hashes don't match - authentication failed");
    return SEED_ERROR_AUTH_FAILED;
}

/**
 * @brief Extract password hash directly from password
 */
static int jwt_extract_password_hash(const char *password, char *hash_out)
{
    if (!password || !hash_out) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    unsigned char hash_bytes[32];
    return jwt_hash_password(password, hash_bytes, hash_out);
}

/**
 * @brief Extract password hash from JWT token by decoding payload
 */
static int jwt_extract_hash_from_token(const char *token, char *hash_out)
{
    if (!token || !hash_out) {
        return SEED_ERROR_INVALID_ARGS;
    }
    
    /* Find payload section (between first and second dots) */
    char *payload_start = strchr(token, '.');
    if (!payload_start) {
        return SEED_ERROR;
    }
    payload_start++; /* Skip the dot */
    
    char *payload_end = strchr(payload_start, '.');
    if (!payload_end) {
        return SEED_ERROR;
    }
    
    /* Extract payload */
    size_t payload_len = payload_end - payload_start;
    char payload_b64[512];
    if (payload_len >= sizeof(payload_b64)) {
        return SEED_ERROR;
    }
    
    memcpy(payload_b64, payload_start, payload_len);
    payload_b64[payload_len] = '\0';
    
    /* Base64 URL decode payload */
    char payload_json[512];
    int decoded_len = base64url_decode(payload_b64, (unsigned char*)payload_json, sizeof(payload_json) - 1);
    if (decoded_len < 0) {
        return SEED_ERROR;
    }
    payload_json[decoded_len] = '\0';
    
    /* Extract 'sub' field from JSON payload */
    /* Simple string search - in production should use proper JSON parser */
    char *sub_start = strstr(payload_json, "\"sub\":\"");
    if (!sub_start) {
        return SEED_ERROR;
    }
    sub_start += 7; /* Skip "sub":" */
    
    char *sub_end = strchr(sub_start, '\"');
    if (!sub_end) {
        return SEED_ERROR;
    }
    
    /* Extract the hash */
    size_t hash_len = sub_end - sub_start;
    if (hash_len >= 65) { /* SHA256 hash is 64 chars + null terminator */
        return SEED_ERROR;
    }
    
    memcpy(hash_out, sub_start, hash_len);
    hash_out[hash_len] = '\0';
    
    return SEED_OK;
}