/**
 * @file "simple_crypto.h"
 * @author Ben Janis
 * @brief Simplified Crypto API Header
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifdef CRYPTO_EXAMPLE
#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include <stdint.h>
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/random.h"

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 16
#define HASH_SIZE SHA256_DIGEST_SIZE
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16
#define RSA_SIG_SIZE 256
/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using AES-GCM
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Does NOT need to be
 *          a multiple of BLOCK_SIZE
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
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *nonce,
                uint8_t *ciphertext, uint8_t *auth_tag);

/** @brief Decrypts ciphertext using AES-GCM and verifies the authentication tag
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *           ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Does NOT need to be
 *           a multiple of BLOCK_SIZE
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *           the key to use for decryption
 * @param nonce A pointer to a buffer of length GCM_NONCE_SIZE (12 bytes)
 *           containing the same nonce used during encryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *           plaintext will be written to
 * @param auth_tag A pointer to a buffer of length GCM_TAG_SIZE (16 bytes)
 *           containing the authentication tag to verify against
 *
 * @return 0 on success, non-zero for other error (including tag mismatch)
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *nonce,
                uint8_t *plaintext, uint8_t *auth_tag);

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *           to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (32 bytes) where the resulting
 *           hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out);


/** @brief Computes HMAC of data using SHA-256
 * 
 * @param key A pointer to a buffer of length key_len containing the HMAC key
 * @param key_len The length of the HMAC key in bytes
 * @param data A pointer to a buffer of length data_len containing the data to be authenticated
 * @param data_len The length of the data to be authenticated in bytes
 * @param mac_out A pointer to a buffer of length HASH_SIZE (32 bytes) where the resulting HMAC output will be written to
 */
int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
    uint8_t *mac_out);


int rsa_sign(const uint8_t *data, size_t data_len, const uint8_t *private_key, size_t key_len, uint8_t *sig_out);

int rsa_verify(const uint8_t *data, size_t data_len, const uint8_t *sig, const uint8_t *public_key, size_t key_len);
#endif // ECTF_CRYPTO_H
#endif // CRYPTO_EXAMPLE
