#ifndef RSA_IMPL_H
#define RSA_IMPL_H

#include "bn.h"

typedef struct pk{
	DTYPE n[MAX_MODULUS_LENGTH];
	DTYPE e[MAX_PRIME_LENGTH];
	DTYPE r_mod[MAX_MODULUS_LENGTH]; //r_mod=2^MAX_MODULUS_BITS(mod n)
	DTYPE n_inv; //-n_inv*n=1(mod 2^word_size)
}rsa_pk;

typedef struct sk{
	DTYPE p[MAX_PRIME_LENGTH];
	DTYPE q[MAX_PRIME_LENGTH];
	DTYPE d1[MAX_PRIME_LENGTH]; //d1=d mod(p-1)
	DTYPE d2[MAX_PRIME_LENGTH]; //d2=d mod(q-1)
	DTYPE p_inv[MAX_PRIME_LENGTH]; //p_inv*p=1(mod q)
	DTYPE p_mod[MAX_PRIME_LENGTH]; //p_mod=2^MAX_PRIME_BITS(mod p)
	DTYPE q_mod[MAX_PRIME_LENGTH]; //q_mod=2^MAX_PRIME_BITS(mod q)
	DTYPE p0_inv; //-p0_inv*p=1(mod 2^word_size)
	DTYPE q0_inv; //-q0_inv*q=1(mod 2^word_size)
}rsa_sk;

void rsa_encrypt(DTYPE *cipher, DTYPE cipher_len, DTYPE *msg, DTYPE msg_len, const rsa_pk *pk);

void rsa_decrypt(DTYPE *output, DTYPE output_len, DTYPE *cipher, DTYPE cipher_len, const rsa_sk *sk);

#endif
