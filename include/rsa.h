/*
 * This is the header file for code which implements the 
 * RSASSA-PKCS1-v1_5 scheme (signature verification operation) as
 * defined in RFC 3447 published February 2003.
 *
 * Many of the variable names in this code, especially the
 * single character names, were used because those were the names
 * used in the publication.
 */

#ifndef _RSA_H_
#define _RSA_H_

#include <stdint.h>

/*
 * The size of multiple precision integers (such as e, n, and s) is
 * equal to 256 bytes (2048 bits).
 */
#define RSA_MPINT_SIZE 256


/*
 * Large integers s, e, and n are in the big-endian (network) format.
 */
int RSA_verify(uint8_t *m, size_t m_size, uint8_t s[RSA_MPINT_SIZE],
		 	uint8_t e[RSA_MPINT_SIZE], uint8_t n[RSA_MPINT_SIZE]);

#endif