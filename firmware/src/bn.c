#include <stdint.h>
#include <string.h>
#include "bn.h"

//set data to zero
void BN_init(DTYPE *data, DTYPE data_length)
{
	int i;
	for(i=0; i < data_length; i++)
	{
		data[i]=0;
	}
}

//to clarify, digit=1, means data>>1 in bit
void BN_right_shift(DTYPE *data, DTYPE data_length, int digit)
{
	int i=0;
	int j;
	DTYPE former;
	while(i<digit)
	{
		former=0;
		for(j=data_length-1; j>=0; j--)
		{
			if(j>0)
			{
				former=BN_LSB(data[j-1]) << (WORD_SIZE-1);
				data[j]>>=1;
				data[j]+=former;
			}
			else
			{
				data[j]>>=1;
			}
		}
		i++;
	}
}

//to clarify, digit=1, means data<<1 in bit
void BN_left_shift(DTYPE *data, DTYPE data_length, int digit)
{
	int i=0;
	int j;
	DTYPE back;
	while(i<digit)
	{
		back=0;
		for(j=0; j<data_length; j++)
		{
			if(j<data_length-1)
			{
				back=BN_MSB(data[j+1]);
				data[j]<<=1;
				data[j]+=back;
			}
			else
			{
				data[j]<<=1;
			}
		}
		i++;
	}
}

//return if data is equal to 1, with 1 as is, 0 as isn't
int BN_isEqualOne(DTYPE *data, DTYPE data_length)
{
	int i;
	if(data[data_length-1]==1)
	{
		for(i=data_length-2; i>=0; i--)
		{
			if(data[i]!=0) return 0;
			else continue;
		}
		return 1;
	}
	else return 0;
}

//return if data is equal to 0, with 1 as is, 0 as isn't
int BN_isEqualZero(DTYPE *data, DTYPE data_length)
{
	int i;
	for(i=data_length-1; i>=0; i--)
	{
		if(data[i]!=0) return 0;
		else continue;
	}
	return 1;
}

void BN_setOne(DTYPE *data, DTYPE data_length)
{
	int i;
	for(i=0; i<data_length-1; i++)
	{
		data[i]=0;
	}
	data[i]=1;
}

void BN_inc(DTYPE *data, DTYPE data_length)
{
	int i=data_length-1, Carry=0;
	data[i]+=1;
	if(data[i]==0)
	{
		Carry=1;
		for(i=data_length-2; i>=0; i++)
		{
			if(Carry==1) data[i]=data[i]+Carry;
			if(data[i]==0) Carry=1;
			else break;
		}
	}
} //increasa 1

void BN_dec(DTYPE *data, DTYPE data_length)
{
	int i=data_length-1, Borrow=0;
	data[i]-=1;
	if(data[i]==MAX_VAL)
	{
		Borrow=1;
		for(i=data_length-2; i>=0; i++)
		{
			if(Borrow==1) data[i]=data[i]-Borrow;
			if(data[i]==MAX_VAL) Borrow=1;
			else break;
		}
	}
} //decrease 1

//return loc of the first non-zero number
int BN_valid_pos(DTYPE *BN, DTYPE BN_length)
{
	int i;
	for(i=0; i<BN_length; i++)
	{
		if(BN[i]==0) continue;
		else return i;
	}
	return BN_length-1;
}

int BN_valid_bits(DTYPE *m, DTYPE length)
{
	int i=0, j=0;
	while(m[i]==0)
	{
		i++;
	}
	DTYPE m0=m[i];
	while(BN_MSB(m0)!=1)
	{
		m0 <<= 1;
		j++;
	}
	return ((length-i)*WORD_SIZE-j);
}

//a>b return 1, a<b return -1, a=b return 0
int BN_cmp(DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length)
{
	int i, j;
	int pos_a=a_length-BN_valid_pos(a, a_length);
	int pos_b=b_length-BN_valid_pos(b, b_length);
	if(pos_a > pos_b) return 1;
	else if(pos_a < pos_b) return -1;
	else
	{
		pos_a=a_length-pos_a;
		pos_b=b_length-pos_b;
		if(a[pos_a]>b[pos_b]) return 1;
		else if(a[pos_a]<b[pos_b]) return -1;
		else
		{
			for(i=pos_a, j=pos_b; i<a_length && j<b_length; i++, j++)
			{
				if(a[i]==b[j]) continue;
				else if(a[i]>b[j]) return 1;
				else return -1;
			}
			return 0;
		}
	}
}

//assign b to a, a_length=b_length
void BN_assign(DTYPE *a, DTYPE *b, DTYPE b_length)
{
	int i;
	for(i=0; i<b_length; i++)
	{
		a[i]=b[i];
	}
}

//exchange values of a and b
void BN_exchange(DTYPE *a, DTYPE *b, DTYPE length)
{
	DTYPE tmp;
	int i;
	for(i=0; i<length; i++)
	{
		tmp=b[i];
		b[i]=a[i];
		a[i]=tmp;
	}
}

//default a_length>=b_length, r_length=a_length+1
void BN_add(DTYPE *r, DTYPE r_length, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length)
{
	int i, j, k=r_length-1, Carry=0;
	T_DTYPE two_dtype_sum=0;
	for(i=a_length-1, j=b_length-1; j>=0; i--, j--)
	{
		two_dtype_sum=a[i]+b[j]+Carry;
		r[k--]=two_dtype_sum & 0x0000ffff;
		Carry=(two_dtype_sum & 0xffff0000)>>WORD_SIZE;
	}
	for(; i>=0; i--)
	{
		two_dtype_sum=a[i]+Carry;
		r[k--]=two_dtype_sum & 0x0000ffff;
		Carry=(two_dtype_sum & 0xffff0000)>>WORD_SIZE;
	}
	r[k]=Carry;
}

//r=a-b a_length>=b_length by default, r_length=a_length
void BN_sub(DTYPE *r, DTYPE r_length, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length)
{
	int Borrow=0, i, j, k=r_length-1;
	for(i=a_length-1, j=b_length-1; i>=0 && j>=0; i--, j--)
	{
		if(a[i]<b[j]+Borrow)
		{
			r[k--]=a[i]-b[j]+MAX_VAL+1-Borrow;
			Borrow=1;
		}
		else
		{
			r[k--]=a[i]-b[j]-Borrow;
			Borrow=0;
		}
	}
	for(; i>=0; i--)
	{
		if(a[i]<Borrow)
		{
			r[k--]=a[i]+MAX_VAL+1-Borrow;
			Borrow=1;
		}
		else
		{
			r[k--]=a[i]-Borrow;
			Borrow=0;
		}
	}
}

//r=a*a default r_length=a_length*2
void BN_square(DTYPE *s, DTYPE *a, DTYPE a_length)
{
	int i, j;
	DTYPE d, e;
	T_DTYPE C_and_S;
	for(i=a_length-1; i>=0; i--)
	{
		C_and_S=s[i+i+1]+(T_DTYPE)a[i]*a[i];
		s[i+i+1]=(C_and_S & 0x0000ffff);
		d=(C_and_S & 0xffff0000) >> WORD_SIZE;
		e=0;
		for(j=i-1; j>=0; j--)
		{
			C_and_S=s[i+j+1]+(T_DTYPE)a[i]*a[j]+d;
			s[i+j+1]=(C_and_S & 0x0000ffff);
			d=(C_and_S & 0xffff0000) >> WORD_SIZE;
			C_and_S=s[i+j+1]+(T_DTYPE)a[i]*a[j]+e;
			s[i+j+1]=(C_and_S & 0x0000ffff);
			e=(C_and_S & 0xffff0000) >> WORD_SIZE;
		}
		C_and_S=d+e;
		d=(C_and_S & 0x0000ffff);
		e=(C_and_S & 0xffff0000) >> WORD_SIZE;
		C_and_S=s[i]+d;
		s[i]=(C_and_S & 0x0000ffff);
		if(i>=1) s[i-1]=e+((C_and_S & 0xffff0000) >> WORD_SIZE);
	}
}

//r=a*b r_length=a_leng+b_length
void BN_mul(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length)
{
	if(a_length==b_length && BN_cmp(a, a_length, b, b_length)==0)
	{
		BN_square(r, a, a_length);
		return;
	}

	int i, j;
	DTYPE len=a_length+b_length, Carry;
	T_DTYPE multi_tmp;

	BN_init(r, len); //set result to 0

	for(i=b_length-1; i>=0; i--)
	{
		Carry=0;
		for(j=a_length-1; j>=0; j--)
		{
			multi_tmp=r[i+j+1]+(T_DTYPE)b[i]*a[j]+Carry;
			Carry=(multi_tmp & 0xffff0000) >> WORD_SIZE;
			r[i+j+1]=(multi_tmp & 0x0000ffff);
		}
		r[i]=Carry;
	}
}

//r=a(mod n) r_length=n_length, a_length>=n_length
void BN_mod(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *n, DTYPE n_length)
{
	int i, j;
	if(BN_cmp(a, a_length, n, n_length)==-1)
	{
		for(i=n_length-1, j=a_length-1; i>=0 && j>=0; i--, j--)
		{
			r[i]=a[j];
		}
		return;
	}

	DTYPE a_copy[MAX_MODULUS_LENGTH*2+1];
	DTYPE aligned_n[MAX_MODULUS_LENGTH*2+1];
	memset(a_copy, 0, sizeof(a_copy));
	memset(aligned_n, 0, sizeof(aligned_n));

	BN_assign(a_copy, a, a_length);
	BN_init(aligned_n, a_length);
	if(a_length == n_length)
	{
		BN_assign(aligned_n, n, n_length);
	}
	else //a_length>n_length
	{
		for(i=n_length-1; i>=0; i--)
		{
			aligned_n[a_length-n_length+i]=n[i];
		}
	}

	int ba=BN_valid_bits(a, a_length);
	int bn=BN_valid_bits(n, n_length);
	if(ba>bn) BN_left_shift(aligned_n, a_length, ba-bn);
	for(i=0; i<=(ba-bn); i++)
	{
		if(BN_cmp(a_copy, a_length, aligned_n, a_length)!=-1)
		{
			BN_sub(a_copy, a_length, a_copy, a_length, aligned_n, a_length);
		}
		BN_right_shift(aligned_n, a_length, 1);
	}
	for(j=a_length-1; j+n_length-a_length>=0; j--)
	{
		r[j+n_length-a_length]=a_copy[j];
	}

	memset(a_copy, 0, sizeof(a_copy));
	memset(aligned_n, 0, sizeof(aligned_n));
}

//r=a*b(mod n) default r_length=n_length use multiply then reduce method
void BN_mod_mul(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length, DTYPE *n, DTYPE n_length)
{
	DTYPE rr[MAX_MODULUS_LENGTH*2+1];
	memset(rr, 0, sizeof(rr));

	BN_mul(rr, a, a_length, b, b_length);
	BN_mod(r, rr, a_length+b_length, n, n_length);
	memset(rr, 0, sizeof(rr));
}

//compute a_inv, a_inv*a=1(mod 2^WORD_SIZE)
//a_inv and a is a DTYPE
void BN_MonMod_inv(DTYPE *a_inv, DTYPE *a, DTYPE a_length)
{
	DTYPE y[2]={ 0, 1 }, modulus[2]={ 0, 2 }, r_tmp[2]={ 0 }, tmp[3]={0};
	int i;

	for(i=2; i<=WORD_SIZE; i++)
	{
		BN_left_shift(modulus, 2, 1);
		BN_mod_mul(r_tmp, y, 2, a, a_length, modulus, 2);
		BN_right_shift(modulus, 2, 1);
		if(BN_cmp(r_tmp, 2, modulus, 2)==1)
		{
			BN_add(tmp, 3, y, 2, modulus, 2);
			y[0]=tmp[1];
			y[1]=tmp[2];
		}
		BN_left_shift(modulus, 2, 1);
	}
	*a_inv=y[1];
}

//special case: compute Montgomery Product with n as pk->n
void BN_MonPro_n(DTYPE *r, DTYPE *a, DTYPE *b, DTYPE *n, DTYPE n_inv)
{
    int i, j;
    DTYPE mm, Carry=0;
	DTYPE t[2*MAX_MODULUS_LENGTH]={0};
	DTYPE u[2*MAX_MODULUS_LENGTH+1]={0};
	DTYPE r_tmp[MAX_MODULUS_LENGTH+1]={0};
	T_DTYPE tmp=0;
	T_DTYPE modulus=0x00010000, mul;

	BN_mul(t, a, MAX_MODULUS_LENGTH, b, MAX_MODULUS_LENGTH);
    for(i=2*MAX_MODULUS_LENGTH-1; i>=MAX_MODULUS_LENGTH; i--)
	{
        Carry=0;
		mul=(t[i]*n_inv)%modulus;
		mm=(mul & 0x0000ffff);
        for(j=MAX_MODULUS_LENGTH-1; j>=0; j--)
		{
            tmp=t[i+j-MAX_MODULUS_LENGTH+1]+mm*n[j]+Carry;
            Carry=(tmp & 0xffff0000) >> WORD_SIZE;
			t[i+j-MAX_MODULUS_LENGTH+1]=(tmp & 0x0000ffff);
        }
        for(j=i-MAX_MODULUS_LENGTH; j>=0; j--)
		{
            tmp=t[j]+Carry;
            Carry=(tmp & 0xffff0000) >> WORD_SIZE;
            t[j]=(tmp & 0x0000ffff);
        }
    }
    u[0]=Carry;
	for(i=1; i<2*MAX_MODULUS_LENGTH+1; i++)
	{
		u[i]=t[i-1];
	}

    int bits=BN_valid_bits(n, MAX_MODULUS_LENGTH);
	if(bits==MAX_MODULUS_BITS)
	{
		for(i=MAX_MODULUS_LENGTH, j=MAX_MODULUS_LENGTH; i>=0 && j>=0; i--, j--)
		{
			r_tmp[j]=u[i];
		}
		if(BN_cmp(r_tmp, MAX_MODULUS_LENGTH+1, n, MAX_MODULUS_LENGTH)==1)
		{
			BN_sub(r_tmp, MAX_MODULUS_LENGTH+1, r_tmp, MAX_MODULUS_LENGTH+1, n, MAX_MODULUS_LENGTH);
		}
		for(i=MAX_MODULUS_LENGTH, j=MAX_MODULUS_LENGTH-1; i>=0 && j>=0; i--, j--)
		{
			r[j]=r_tmp[i];
		}
	}
	else
	{
		BN_right_shift(u, 2*MAX_MODULUS_LENGTH+1, bits);
		for(i=2*MAX_MODULUS_LENGTH, j=MAX_MODULUS_LENGTH; i>=0 && j>=0; i--, j--)
		{
			r_tmp[j]=u[i];
		}
		while(BN_cmp(r_tmp, MAX_MODULUS_LENGTH+1, n, MAX_MODULUS_LENGTH)==1)
		{
			BN_sub(r_tmp, MAX_MODULUS_LENGTH+1, r_tmp, MAX_MODULUS_LENGTH+1, n, MAX_MODULUS_LENGTH);
		}
		for(i=MAX_MODULUS_LENGTH, j=MAX_MODULUS_LENGTH-1; i >= 0 && j >= 0; i--, j--)
		{
			r[j]=r_tmp[i];
		}
	}
}

//special case: compute Montgomery Product with n as sk->p, sk->q
void BN_MonPro_p(DTYPE *r, DTYPE *a, DTYPE *b, DTYPE *n, DTYPE n_inv)
{
	int i, j;
	DTYPE mm, Carry=0;
	DTYPE t[2*MAX_PRIME_LENGTH]={ 0 };
	DTYPE u[2*MAX_PRIME_LENGTH+1]={ 0 };
	DTYPE r_tmp[MAX_PRIME_LENGTH+1]={ 0 };
	T_DTYPE tmp=0;
	T_DTYPE modulus=0x00010000, mul;

	BN_mul(t, a, MAX_PRIME_LENGTH, b, MAX_PRIME_LENGTH);
	for(i=2*MAX_PRIME_LENGTH-1; i>=MAX_PRIME_LENGTH; i--)
	{
		Carry=0;
		mul=(t[i]*n_inv)%modulus;
		mm=(mul & 0x0000ffff);
		for(j=MAX_PRIME_LENGTH-1; j >= 0; j--)
		{
			tmp=t[i+j-MAX_PRIME_LENGTH+1]+mm*n[j]+Carry;
			Carry=(tmp & 0xffff0000) >> WORD_SIZE;
			t[i+j-MAX_PRIME_LENGTH+1]=(tmp & 0x0000ffff);
		}
		for(j=i-MAX_PRIME_LENGTH; j >= 0; j--)
		{
			tmp=t[j]+Carry;
			Carry=(tmp & 0xffff0000) >> WORD_SIZE;
			t[j]=(tmp & 0x0000ffff);
		}
	}
	u[0]=Carry;

	for(i=1; i<2*MAX_PRIME_LENGTH+1; i++)
	{
		u[i]=t[i-1];
	}
	for(i=MAX_PRIME_LENGTH; i>=0; i--)
	{
		r_tmp[i]=u[i];
	}
	if(BN_cmp(r_tmp, MAX_PRIME_LENGTH+1, n, MAX_PRIME_LENGTH)!=-1)
	{
		BN_sub(r_tmp, MAX_PRIME_LENGTH+1, r_tmp, MAX_PRIME_LENGTH+1, n, MAX_PRIME_LENGTH);
	}
	for(i=MAX_PRIME_LENGTH-1; i>=0; i--)
	{
		r[i]=r_tmp[i+1];
	}
}

void BN_MonPro(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length, DTYPE *n, DTYPE n_length, DTYPE n_inv)
{
	if(n_length == MAX_MODULUS_LENGTH) BN_MonPro_n(r, a, b, n, n_inv);
	else BN_MonPro_p(r, a, b, n, n_inv);
}

void BN_MonExp_n(DTYPE *result, DTYPE *a, DTYPE *e, DTYPE *n, DTYPE *r, DTYPE inv)
{
	int bits;
	DTYPE e_copy[MAX_PRIME_LENGTH]={0};
	DTYPE a_r[MAX_MODULUS_LENGTH]={0};
	DTYPE x_r[MAX_MODULUS_LENGTH]={0};
	DTYPE one[MAX_MODULUS_LENGTH]={0};
	one[MAX_MODULUS_LENGTH-1]=1;
	BN_assign(e_copy, e, MAX_PRIME_LENGTH);
	BN_assign(x_r, r, MAX_MODULUS_LENGTH);
	BN_mod_mul(a_r, a, MAX_MODULUS_LENGTH, x_r, MAX_MODULUS_LENGTH, n, MAX_MODULUS_LENGTH);
	bits=BN_valid_bits(e, MAX_PRIME_LENGTH);
	while(BN_MSB(e_copy[0])!=1)
	{
		BN_left_shift(e_copy, MAX_PRIME_LENGTH, 1);
	}
	while(bits>0)
	{
		BN_MonPro_n(x_r, x_r, x_r, n, inv);
		if(BN_MSB(e_copy[0]) == 1)
		{
			BN_MonPro_n(x_r, a_r, x_r, n, inv);
		}
		BN_left_shift(e_copy, MAX_PRIME_LENGTH, 1);
		bits--;
	}
	BN_MonPro_n(result, x_r, one, n, inv);
}

//Montgomery Method to compute result=a^e(mod n)
void BN_MonExp_p(DTYPE *result, DTYPE *a, DTYPE *e, DTYPE *n, DTYPE *r, DTYPE inv)
{
	int bits;
	DTYPE e_copy[MAX_PRIME_LENGTH]={0};
	DTYPE a_r[MAX_PRIME_LENGTH]={0};
	DTYPE x_r[MAX_PRIME_LENGTH]={0};
	DTYPE one[MAX_PRIME_LENGTH]={0};
	one[MAX_PRIME_LENGTH-1]=1;
	BN_assign(e_copy, e, MAX_PRIME_LENGTH);
	BN_assign(x_r, r, MAX_PRIME_LENGTH);
	BN_mod_mul(a_r, a, MAX_MODULUS_LENGTH, x_r, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH);
	bits=BN_valid_bits(e, MAX_PRIME_LENGTH);
	while(BN_MSB(e_copy[0])!=1)
	{
		BN_left_shift(e_copy, MAX_PRIME_LENGTH, 1);
	}
	while(bits>0)
	{
		BN_MonPro_p(x_r, x_r, x_r, n, inv);
		if(BN_MSB(e_copy[0]) == 1)
		{
			BN_MonPro_p(x_r, a_r, x_r, n, inv);
		}
		BN_left_shift(e_copy, MAX_PRIME_LENGTH, 1);
		bits--;
	}
	BN_MonPro_p(result, x_r, one, n, inv);
}

void BN_MonExp(DTYPE *result, DTYPE *a, DTYPE a_length, DTYPE *e, DTYPE e_length, DTYPE *n, DTYPE n_length, DTYPE *r, DTYPE inv)
{
	if(n_length == MAX_MODULUS_LENGTH) BN_MonExp_n(result, a, e, n, r, inv);
	else  BN_MonExp_p(result, a, e, n, r, inv);
}
