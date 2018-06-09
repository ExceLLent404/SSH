/*
 * This is the header file for code which implements the Secure
 * Hash Algorithm 1 (SHA1) as defined in RFC 3174 published
 * September 2001.
 *
 * Many of the variable names in this code, especially the
 * single character names, were used because those were the names
 * used in the publication.
 */

#ifndef _SHA1_H_
#define _SHA1_H_

#include <stdint.h>

#define SHA1_HASH_SIZE 20

void hash(uint8_t *data, size_t size, uint8_t digest[SHA1_HASH_SIZE]);

#endif
