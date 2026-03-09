#include "rsa_impl.h"

//use pk to encrypt msg, output is cipher
void rsa_encrypt(DTYPE *cipher, DTYPE cipher_len, DTYPE *msg, DTYPE msg_len, const rsa_pk *pk)
{
	BN_MonExp(cipher, msg, msg_len, (DTYPE *)pk->e, MAX_PRIME_LENGTH, (DTYPE *)pk->n, MAX_MODULUS_LENGTH, (DTYPE *)pk->r_mod, pk->n_inv);
}

//use sk to decrypt cipher, result is saved in output (CRT method)
void rsa_decrypt(DTYPE *output, DTYPE output_len, DTYPE *cipher, DTYPE cipher_len, const rsa_sk *sk)
{
	int i;
	DTYPE M1[MAX_PRIME_LENGTH]={0};
	DTYPE M2[MAX_PRIME_LENGTH]={0};
	DTYPE M_tmp[MAX_PRIME_LENGTH]={0};
	DTYPE r1_tmp[MAX_PRIME_LENGTH]={0};
	DTYPE r2_tmp[MAX_MODULUS_LENGTH]={0};
	DTYPE out[MAX_MODULUS_LENGTH+1] = {0};

	BN_MonExp(M1, cipher, cipher_len, (DTYPE *)sk->d1, MAX_PRIME_LENGTH, (DTYPE *)sk->p, MAX_PRIME_LENGTH, (DTYPE *)sk->p_mod, sk->p0_inv);
	BN_MonExp(M2, cipher, cipher_len, (DTYPE *)sk->d2, MAX_PRIME_LENGTH, (DTYPE *)sk->q, MAX_PRIME_LENGTH, (DTYPE *)sk->q_mod, sk->q0_inv);
	if(BN_cmp(M2, MAX_PRIME_LENGTH, M1, MAX_PRIME_LENGTH)>=0) //M2>=M1
	{
		BN_sub(M_tmp, MAX_PRIME_LENGTH, M2, MAX_PRIME_LENGTH, M1, MAX_PRIME_LENGTH);
	}
	else //M1>M2
	{
		BN_sub(M_tmp, MAX_PRIME_LENGTH, M1, MAX_PRIME_LENGTH, M2, MAX_PRIME_LENGTH);
		BN_mod(M_tmp, M_tmp, MAX_PRIME_LENGTH, (DTYPE *)sk->q, MAX_PRIME_LENGTH);
		BN_sub(M_tmp, MAX_PRIME_LENGTH, (DTYPE *)sk->q, MAX_PRIME_LENGTH, M_tmp, MAX_PRIME_LENGTH);
	}
	BN_mod_mul(r1_tmp, M_tmp, MAX_PRIME_LENGTH, (DTYPE *)sk->p_inv, MAX_PRIME_LENGTH, (DTYPE *)sk->q, MAX_PRIME_LENGTH);
	BN_mul(r2_tmp, r1_tmp, MAX_PRIME_LENGTH, (DTYPE *)sk->p, MAX_PRIME_LENGTH);
	BN_add(out, MAX_MODULUS_LENGTH+1, r2_tmp, MAX_MODULUS_LENGTH, M1, MAX_PRIME_LENGTH);

	for(i=0; i<MAX_MODULUS_LENGTH; i++)
	{
		output[i] = out[i+1];
	}
}
