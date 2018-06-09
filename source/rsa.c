#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "../include/rsa.h"
#include "../include/sha1.h"

/* EMSA-PKCS1-v1_5 encoding */
static void encode(uint8_t *EM, size_t emLen, uint8_t *M, size_t mLen)
{
	int i, shift = 0;
	uint8_t H[SHA1_HASH_SIZE];
	uint8_t algorithm_id[] = {
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
		0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
	};

	hash(M, mLen, H);

	EM[shift++] = 0x00;
	EM[shift++] = 0x01;
	for (i = 0; i < emLen - sizeof(algorithm_id) - SHA1_HASH_SIZE - 3; ++i)
		EM[i + shift] = 0xff;
	shift += emLen - sizeof(algorithm_id) - SHA1_HASH_SIZE - 3;
	EM[shift++] = 0x00;
	for (i = 0; i < sizeof(algorithm_id); ++i)
		EM[i + shift] = algorithm_id[i];
	shift += sizeof(algorithm_id);
	for (i = 0; i < SHA1_HASH_SIZE; ++i)
		EM[i + shift] = H[i];
}

/* RSASSA-PKCS1-V1_5-VERIFY */
int RSA_verify(uint8_t *original_byte, size_t original_size,
		uint8_t s_byte[RSA_MPINT_SIZE], uint8_t e_byte[RSA_MPINT_SIZE],
		 uint8_t n_byte[RSA_MPINT_SIZE])
{
	int i, shift, error;
	mpz_t m, s, e, n;
	uint8_t *em1 = (uint8_t *) calloc(RSA_MPINT_SIZE, sizeof(uint8_t));
	uint8_t *em2 = (uint8_t *) calloc(RSA_MPINT_SIZE, sizeof(uint8_t));

	mpz_init(m);
	mpz_init(s);
	mpz_init(e);
	mpz_init(n);

	mpz_import(s, RSA_MPINT_SIZE, 1, sizeof(uint8_t), 1, 0, s_byte);
	mpz_import(e, RSA_MPINT_SIZE, 1, sizeof(uint8_t), 1, 0, e_byte);
	mpz_import(n, RSA_MPINT_SIZE, 1, sizeof(uint8_t), 1, 0, n_byte);

	mpz_powm(m, s, e, n);

	/*
	 * The size of m can be less than the size of the allocated
	 * memory, i.e. RSA_MPINT_SIZE. Calculate how many bytes to
	 * skip before exporting the number, and set these bytes to
	 * 0x00's.
	 */
	shift = RSA_MPINT_SIZE - (mpz_sizeinbase(m, 2) + 7) / 8;
	for (i = 0; i < shift; ++i)
		em1[i] = 0x00;
	mpz_export(em1 + shift, NULL, 1, sizeof(uint8_t), -1, 0, m);

	mpz_clear(m);
	mpz_clear(s);
	mpz_clear(e);
	mpz_clear(n);

	encode(em2, RSA_MPINT_SIZE, original_byte, original_size);

	error = memcmp(em1, em2, RSA_MPINT_SIZE);

	free(em1);
	free(em2);

	if(error)
		return 1;
	return 0;
}
