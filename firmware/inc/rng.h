#ifndef RNG_H
#define RNG_H

#include <stdint.h>
#include <stddef.h>

#endif
 
/**
 * @brief Initializes the True Random Number Generator (TRNG) hardware.
*/
void rng_init(void);


/**
 * @brief Retrieves a random 32-bit word from the TRNG.
 * 
 * @return A random 32-bit unsigned integer.
 */
uint32_t trng_get_word(void);

/**
 * @brief Generates a nonce of the specified length and stores it in the provided output buffer.
 * 
 * @param out Pointer to the buffer where the generated nonce will be stored.
 * @param len The length of the nonce to be generated, in bytes.
 */
void generate_nonce(uint8_t *out, size_t len);
