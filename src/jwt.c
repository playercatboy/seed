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
    
    /* Simple comparison for now - in production, should parse and validate properly */
    /* Extract and compare just the password hash part */
    char *gen_payload_start = strchr(generated_token, '.');
    char *gen_payload_end = NULL;
    char *tok_payload_start = strchr(token, '.');
    char *tok_payload_end = NULL;
    
    if (gen_payload_start && tok_payload_start) {
        gen_payload_start++;
        tok_payload_start++;
        gen_payload_end = strchr(gen_payload_start, '.');
        tok_payload_end = strchr(tok_payload_start, '.');
        
        if (gen_payload_end && tok_payload_end) {
            /* Compare payload lengths */
            size_t gen_len = gen_payload_end - gen_payload_start;
            size_t tok_len = tok_payload_end - tok_payload_start;
            
            /* For now, just check if password hashes match in payload */
            /* In production, should properly decode and parse JSON */
            if (gen_len == tok_len && 
                memcmp(gen_payload_start, tok_payload_start, gen_len) == 0) {
                return SEED_OK;
            }
        }
    }
    
    return SEED_ERROR_AUTH_FAILED;
}