#include <stdint.h>
#include <time.h>
#include <gmp.h>
#include "../include/dh.h"

void DH_generate_x(uint8_t x_byte[DH_MPINT_SIZE])
{
	int i, shift;
	mpz_t x, q;
	gmp_randstate_t state;

	mpz_init(x);
	mpz_init(q);
	gmp_randinit_default(state);
	gmp_randseed_ui(state, time(NULL));

	/* q = (p - 1) / 2 */
	mpz_set_str(q, DH_P, 16);
	mpz_sub_ui(q, q, 1);
	mpz_cdiv_q_ui(q, q, 2);

	/* generate x: x < q */
	mpz_urandomb(x, state, DH_MPINT_SIZE * 8 - 1);

	/*
	 * The size of the number x can be less than the size of the
	 * allocated memory, i.e. DH_MPINT_SIZE. Calculate how many
	 * bytes to skip before exporting the number, and set
	 * these bytes to 0x00's.
	 */
	shift = DH_MPINT_SIZE - (mpz_sizeinbase(x, 2) + 7) / 8;
	for (i = 0; i < shift; ++i)
		x_byte[i] = 0x00;
	mpz_export(x_byte + shift, NULL, 1, sizeof(uint8_t), -1, 0, x);
	
	mpz_clear(x);
	mpz_clear(q);
	gmp_randclear(state);
}

void DH_compute_e(uint8_t e_byte[DH_MPINT_SIZE], uint8_t x_byte[DH_MPINT_SIZE])
{
	int i, shift;
	mpz_t e, g, x, p;
	
	mpz_init(e);
	mpz_init_set_ui(g, DH_G);
	mpz_init(x);
	mpz_init_set_str(p, DH_P, 16);

	mpz_import(x, DH_MPINT_SIZE, 1, sizeof(uint8_t), 1, 0, x_byte);

	mpz_powm(e, g, x, p);

	/*
	 * The size of the number e can be less than the size of the
	 * allocated memory, i.e. DH_MPINT_SIZE. Calculate how many
	 * bytes to skip before exporting the number, and set
	 * these bytes to 0x00's.
	 */
	shift = DH_MPINT_SIZE - (mpz_sizeinbase(e, 2) + 7) / 8;
	for (i = 0; i < shift; ++i)
		e_byte[i] = 0x00;
	mpz_export(e_byte + shift, NULL, 1, sizeof(uint8_t), -1, 0, e);
	
	mpz_clear(e);
	mpz_clear(g);
	mpz_clear(x);
	mpz_clear(p);
}

void DH_compute_K(uint8_t K_byte[DH_MPINT_SIZE], uint8_t f_byte[DH_MPINT_SIZE],
						uint8_t x_byte[DH_MPINT_SIZE])
{
	int i, shift;
	mpz_t K, f, x, p;
	
	mpz_init(K);
	mpz_init(f);
	mpz_init(x);
	mpz_init_set_str(p, DH_P, 16);

	mpz_import(x, DH_MPINT_SIZE, 1, sizeof(uint8_t), 1, 0, x_byte);
	mpz_import(f, DH_MPINT_SIZE, 1, sizeof(uint8_t), 1, 0, f_byte);

	mpz_powm(K, f, x, p);

	/*
	 * The size of the number K can be less than the size of the
	 * allocated memory, i.e. DH_MPINT_SIZE. Calculate how many
	 * bytes to skip before exporting the number, and set
	 * these bytes to 0x00's.
	 */
	shift = DH_MPINT_SIZE - (mpz_sizeinbase(K, 2) + 7) / 8;
	for (i = 0; i < shift; ++i)
		K_byte[i] = 0x00;
	mpz_export(K_byte + shift, NULL, 1, sizeof(uint8_t), -1, 0, K);
	
	mpz_clear(K);
	mpz_clear(f);
	mpz_clear(x);
	mpz_clear(p);
}
