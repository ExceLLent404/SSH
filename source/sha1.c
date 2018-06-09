#include <stdint.h>
#include <string.h>
#include "../include/sha1.h"

#define BLOCK_SIZE 64

/* Circular left shift */
#define ROTATE(n, word) \
	(((word) << (n)) | ((word) >> (32 - (n))))

static uint32_t H[5];

static void process_block(uint8_t block[BLOCK_SIZE])
{
	int t;
	uint32_t temp, W[80];
	uint32_t A = H[0], B = H[1], C = H[2], D = H[3], E = H[4];
	uint32_t K[] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

	for (t = 0; t < 16; ++t) {
		W[t] = block[t * 4] << 24;
		W[t] |= block[t * 4 + 1] << 16;
		W[t] |= block[t * 4 + 2] << 8;
		W[t] |= block[t * 4 + 3];
	}
	
	for (t = 16; t < 80; ++t)
		W[t] = ROTATE(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

	for(t = 0; t < 20; t++) {
		temp = ROTATE(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
		E = D;
		D = C;
		C = ROTATE(30, B);
		B = A;
		A = temp;
	}

	for(t = 20; t < 40; t++) {
		temp = ROTATE(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = ROTATE(30, B);
		B = A;
		A = temp;
	}

	for(t = 40; t < 60; t++) {
		temp = ROTATE(5, A) + ((B & C) | (B & D) | (C & D)) +
							 E + W[t] + K[2];
		E = D;
		D = C;
		C = ROTATE(30, B);
		B = A;
		A = temp;
	}

	for(t = 60; t < 80; t++) {
		temp = ROTATE(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = ROTATE(30, B);
		B = A;
		A = temp;
	}

	H[0] += A;
	H[1] += B;
	H[2] += C;
	H[3] += D;
	H[4] += E;

}

void hash(uint8_t *data, size_t size, uint8_t digest[SHA1_HASH_SIZE])
{
	int i, r;
	uint8_t temp[BLOCK_SIZE];

	H[0] = 0x67452301;
	H[1] = 0xEFCDAB89;
	H[2] = 0x98BADCFE;
	H[3] = 0x10325476;
	H[4] = 0xC3D2E1F0;

	for (i = 0; i < size / BLOCK_SIZE; ++i)
		process_block(data + i * BLOCK_SIZE);

	/* Message Padding */
	r = size % BLOCK_SIZE;
	memcpy(temp, data + i * BLOCK_SIZE, r);
	temp[r] = 0x80;
	for (i = r + 1; i < 56; ++i)
		temp[i] = 0x00;
	if (r > 55) {
		for (i = r + 1; i < 64; ++i)
			temp[i] = 0x00;
		process_block(temp);
		memset(temp, 0, BLOCK_SIZE - 8);
	}

	size *= 8;
	for (i = 0; i < 8; ++i)
		temp[i + 56] = (size >> (56 - i * 8)) & 0xff;

	process_block(temp);
	
	for(i = 0; i < SHA1_HASH_SIZE / 4; ++i) {
		digest[i * 4] = (H[i] >> 24) & 0xff;
		digest[i * 4 + 1] = (H[i] >> 16) & 0xff;
		digest[i * 4 + 2] = (H[i] >> 8) & 0xff;
		digest[i * 4 + 3] = H[i] & 0xff;
	}
}