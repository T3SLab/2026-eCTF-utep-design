/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifdef CRYPTO_EXAMPLE

// used for the encryption function
#include "simple_crypto.h"
#include "security.h"
#include <stdint.h>
#include <string.h>


/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Does NOT need to be
 *          a multiple of BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param nonce A pointer to a buffer of length GCM_NONCE_SIZE (12 bytes)
 *          containing a unique nonce for this encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 * @param auth_tag A pointer to a buffer of length GCM_TAG_SIZE (16 bytes)
 *          where the authentication tag will be written to
 *
 * @return 0 on success, non-zero for other error
 */

//  TODO 1
// // encryption

// INPUT
// - plaintext -- The raw file contents (uint8_t*, up to 8192 bytes)
// - len -- Length of the plaintext (size_t, does NOT need to be multiple of 16)
// - key -- The slot's AES key (uint8_t*, 16 or 32 bytes depending on your design)
// - nonce -- A 12-byte unique value (uint8_t[12], MUST be unique per encryption)


// OUTPUT
//  ciphertext -- Encrypted data (uint8_t*, same length as plaintext)
//  - auth_tag -- 16-byte authentication tag (uint8_t[16])
//  -  Return value: 0 on success, non-zero on error

// on the parameters we need nonce, it is a 12 byte number -  If you encrypt the same file twice with the same key,
// without a nonce the ciphertext would be identical both times

// we also need to add auth_tag -Encryption alone only hides data — it doesn't prove nobody modified it. The auth tag is a cryptographic checksum that proves:
// - The ciphertext was created by someone who knows the key
// - Not a single bit of the ciphertext was changed
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *nonce,
                uint8_t *ciphertext, uint8_t *auth_tag)
{
    // We need to first load the context - this is like the library that does the encrypting

    Aes ctx; // wolfSSL AES context
    int ret;

    // STEP 1: Load the slot's AES key into the context
    // The key is for each slot to create its own encryption
    // so if one is comprimised the other ones will still be safe

    // we will use the wc_AesGcmSetKey function of wolfSSL library to encrypt the data
    // we provide the context, the key for that specific slot, and the key_size defined on simpple_crypto.h
    // 16 bytes
    // Initialize the key
    ret = wc_AesGcmSetKey(&ctx, key, KEY_SIZE);
    if (ret != 0)
        return ret;

    // STEP 2: Encrypt + generate authentication tag
    // with wolfssl we only need one single call to encryp the whole file
    // we don't need to break it into blocks
    // Encrypt using AES-GCM
    ret = wc_AesGcmEncrypt(
        &ctx,                   // AES context with key loaded
        ciphertext,             // OUTPUT: encrypted data (same size as plaintext)
        plaintext,              // INPUT: raw file contents
        len,                    // Length of data (any size — GCM handles it)
        nonce,                  // 12-byte unique nonce
        GCM_NONCE_SIZE,         // Nonce length (always 12 for GCM)
        auth_tag,               // OUTPUT: 16-byte authentication tag
        GCM_TAG_SIZE,           // Tag length (16 = full security)
        NULL,                   // AAD (Additional Authenticated Data) — optional
        0                       // AAD length (0 = no AAD for now)
    );

    return ret; // 0 = success
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Does NOT need to be
 *          a multiple of BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param nonce A pointer to a buffer of length GCM_NONCE_SIZE (12 bytes)
 *          containing the same nonce used during encryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 * @param auth_tag A pointer to a buffer of length GCM_TAG_SIZE (16 bytes)
 *          containing the authentication tag to verify against
 *
 * @return 0 on success, non-zero for other error (including tag mismatch)
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *nonce,
                uint8_t *plaintext, uint8_t *auth_tag)
{
    Aes ctx;
    int ret;

    // Load the AES key into the GCM context
    ret = wc_AesGcmSetKey(&ctx, key, KEY_SIZE);
    if (ret != 0)
        return ret;

    // Decrypt + verify authentication tag in one call
    // If the tag doesn't match (data was tampered with), this returns a non-zero error
    ret = wc_AesGcmDecrypt(
        &ctx,       // AES context with key loaded
        plaintext,  // OUTPUT: decrypted data
        ciphertext,  // INPUT: encrypted data
        len,     // Length of ciphertext (same as original plaintext length)
        nonce,  // 12-byte nonce (must be the SAME one used during encryption)
        GCM_NONCE_SIZE,      // Nonce length (12)
        auth_tag,        // INPUT: 16-byte tag to verify against
        GCM_TAG_SIZE,     // Tag length (16)
        NULL,      // AAD pointer (NULL = no AAD, matching your encrypt)
        0           // AAD length (0)
    );

    return ret; // 0 = success, non-zero = decryption failed or tag mismatch
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    // Pass values to hash
    return wc_Sha256Hash((uint8_t *)data, len, hash_out);
}

int hmac_sha256(const uint8_t *key, size_t key_len,const uint8_t *data, size_t data_len,
        uint8_t *mac_out) {
    Hmac hmac;
    int ret;
    
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0){
        return ret;
    }
    
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)key_len);
    if (ret != 0){
        return ret;
    }
    
    ret = wc_HmacUpdate(&hmac, data, (word32)data_len);
    if (ret != 0){
     return ret;
    }
    
    ret = wc_HmacFinal(&hmac, mac_out);
    wc_HmacFree(&hmac);
    return ret;
}

#endif // CRYPTO_EXAMPLE
