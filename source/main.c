/*
 * This file implements the Secure Shell (SSH) Transport Layer
 * protocol as defined in RFC 4253 published January 2006.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/sha1.h"
#include "../include/dh.h"
#include "../include/rsa.h"

#define SSH_PORT 22

char *prog_name;

/* 
 * pre_hash = a || b || c || ... . Where || is concatenation of some
 * data a, b, c etc. It is a temporary storage for data which will
 * then be hashed.
 */
uint8_t *pre_hash;
size_t pre_hash_size;
uint8_t K[DH_MPINT_SIZE];	/* a shared secret  */
uint8_t H[SHA1HashSize];	/* an exchange hash */
uint8_t session_id[SHA1HashSize];
uint8_t IV_ctos[SHA1HashSize], IV_stoc[SHA1HashSize];
uint8_t encryption_k_ctos[SHA1HashSize], encryption_k_stoc[SHA1HashSize];
uint8_t integrity_k_ctos[SHA1HashSize], integrity_k_stoc[SHA1HashSize];

void print_error(const char *str)
{
	fprintf(stderr, "%s: %s", prog_name, str);
	if (errno)
		fprintf(stderr, ": %s", strerror(errno));
}

/* Data types */
#define RAW_T		0
#define MPINT_T		1
#define STRING_T	2

/*
 * The function will append data to pre_hash storage. It takes into
 * account data type.
 */

void append(uint8_t *data, uint32_t length, int data_type)
{
	size_t tail_size = 0;

	/*
	 * Multiple precision integers and strings must be stored
	 * with its length.
	*/
	if (data_type != RAW_T) {
		tail_size += sizeof(length);
	}

	/* 
	 * If the most significant bit would be equal to one for a 
	 * positive number, the number must be preceded by a zero
	 * byte. Thus, its length will increace by one.
	 */
	if ((data_type == MPINT_T) && (*data & 0x80)) {
		length++;
	}
	tail_size += length;

	pre_hash = (uint8_t *) realloc(pre_hash, pre_hash_size + tail_size);

	if (data_type != RAW_T) {
		*(uint32_t *) (pre_hash + pre_hash_size) = htonl(length);
		pre_hash_size += sizeof(length);
	}
	if ((data_type == MPINT_T) && (*data & 0x80)) {
		*(pre_hash + pre_hash_size) = 0;
		pre_hash_size++;
		length--;
	}

	memcpy(pre_hash + pre_hash_size, data, length);
	pre_hash_size += length;
}

/* Returns a new socket descriptor */
int initialize_connection(char *address)
{
	int network_socket;
	int conversion_status;
	struct sockaddr_in server_address;

	if ((network_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		print_error("cannot create socket");
		close(network_socket);
		exit(EXIT_FAILURE);
	}

	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(SSH_PORT);
	if ((conversion_status = inet_pton(AF_INET, address,
					 &server_address.sin_addr)) == -1) {
		print_error("address conversion failed");
		close(network_socket);
		exit(EXIT_FAILURE);
	} else if (!conversion_status) {
		print_error("input isn't a valid IP address");
		close(network_socket);
		exit(EXIT_FAILURE);
	}

	printf("Connecting to %s\n", address);
	if (connect(network_socket, (struct sockaddr *) &server_address,
		 			sizeof(server_address)) == -1) {
		print_error("connection failed");
		close(network_socket);
		exit(EXIT_FAILURE);
	}

	return network_socket;
}

#define MAX_BUF_SIZE 1024

void exchange_protocol_versions(int network_socket)
{
	char identification_string[] = "SSH-2.0-EDU\r\n";
	char server_response[MAX_BUF_SIZE];
	int numbytes;

	append((uint8_t *) identification_string,
				strlen(identification_string) - 2, STRING_T);

	printf("Sending the identification string: %s", identification_string);
	if (send(network_socket, identification_string, 
				strlen(identification_string), 0) == -1) {
		print_error("cannot send the identification string");
		close(network_socket);
		exit(EXIT_FAILURE);		
	}

	if ((numbytes = recv(network_socket, server_response, 
						MAX_BUF_SIZE - 1, 0)) == -1) {
		print_error("cannot receive data");
		close(network_socket);
		exit(EXIT_FAILURE);
	}
	if (numbytes == 0) {
		print_error("the server has closed the connection");
		close(network_socket);
		exit(EXIT_FAILURE);
	}
	server_response[numbytes] = '\0';
	printf("The server sent the data:\n%s", server_response);

	append((uint8_t *) server_response, numbytes - 2, STRING_T);
}

void set_random_bytes(uint8_t *destination, int numbytes)
{
	int i, j, remainder, step_size = sizeof(uint32_t);
	int step = numbytes / step_size;
	uint32_t random_value;
	uint8_t *ptr = (uint8_t *) &random_value;

	srand(time(NULL));
	for (i = 0; i < step; ++i) {
		random_value = rand();
		*(uint32_t *) (destination + i * step_size) = random_value;
	}
	if (remainder = numbytes % sizeof(uint32_t))
		random_value = rand();
	for (j = 0; j < remainder; ++j)
		destination[j + i * step_size] = ptr[j];
}

/*
 * The function calculates the packet size, which is formatted
 * according to the binary packet protocol.
 */
size_t get_packet_size(size_t payload_size, size_t cipher_block_size, 
								int mac_length)
{
	int piece_size = (cipher_block_size > 8) ? cipher_block_size : 8;
	size_t packet_size, padding_length = 4;

	packet_size = sizeof(uint32_t) + sizeof(uint8_t) + payload_size;
	if ((packet_size + padding_length) % piece_size)
		padding_length += piece_size - 
				(packet_size + padding_length) % piece_size;
	packet_size += padding_length + mac_length;

	return packet_size;
}

/*
 * The function wrap a message to a packet, which is formatted
 * according to the binary packet protocol.
 *
 * The message must be set by calling one of the set_msg functions
 * before invoking this function.
 */
void wrap_message(uint8_t *data_packet, size_t packet_size, 
					size_t payload_size, int mac_length)
{
	int shift = 0;
	uint32_t packet_length;
	uint8_t padding_length;

	packet_length = packet_size - sizeof(uint32_t) - mac_length;
	padding_length = packet_length  - sizeof(uint8_t)- payload_size;

	*(uint32_t *) (data_packet) = htonl(packet_length);
	shift += sizeof(uint32_t);
	data_packet[shift++] = padding_length;
	shift += payload_size;
	set_random_bytes(data_packet + shift, padding_length);
	/*
	shift += padding_length;
	if (mac_length > 0)
		There must be the MAC
	*/
}

#define NAME_LIST_SIZE 10
#define COOKIE_SIZE 16

size_t get_kexinit_msg_size(char *name_list[NAME_LIST_SIZE])
{
	int i;
	size_t size;

	size = sizeof(uint8_t) + COOKIE_SIZE + 
					NAME_LIST_SIZE * sizeof(uint32_t);
	for (i = 0; i < NAME_LIST_SIZE; ++i)
		size += strlen(name_list[i]);
	size += sizeof(uint8_t) + sizeof(uint32_t);

	return size;
}

#define SSH_MSG_KEXINIT 20
#define FALSE 0
#define TRUE 1

void set_kexinit_msg(uint8_t *data, char *name_list[NAME_LIST_SIZE])
{
	int i, j, length, shift;	
	uint8_t cookie[COOKIE_SIZE];

	set_random_bytes(cookie, COOKIE_SIZE);

	shift = 0;
	data[shift++] = SSH_MSG_KEXINIT;
	for (i = 0; i < COOKIE_SIZE; ++i)
		data[i + shift] = cookie[i];
	shift += COOKIE_SIZE;
	for (i = 0; i < NAME_LIST_SIZE; ++i) {
		length = strlen(name_list[i]);
		*(uint32_t *) (data + shift) = htonl(length);
		shift += sizeof(uint32_t);
		for (j = 0; j < length; ++j)
			data[shift + j] = ((uint8_t *) name_list[i])[j];
		shift += length;
	}
	data[shift++] = FALSE;
	*(uint32_t *) (data + shift) = 0;
}

/* Algoritm Negotiation: the SSH_MSG_KEXINIT message exchange */
void negotiate_algorithms(int network_socket)
{
	int numbytes, shift;
	uint32_t length;
	uint8_t server_response[MAX_BUF_SIZE];
	char *name_list[NAME_LIST_SIZE] = {
		"diffie-hellman-group14-sha1",
		"ssh-rsa",
		"chacha20-poly1305@openssh.com",
		"chacha20-poly1305@openssh.com",
		"hmac-sha1",
		"hmac-sha1",
		"none",
		"none",
		"",
		""
	};
	size_t msg_size = get_kexinit_msg_size(name_list);
	size_t packet_size = get_packet_size(msg_size, 0, 0);
	uint8_t *data_packet = (uint8_t *) calloc(packet_size, 
							sizeof(uint8_t));

	shift = sizeof(uint32_t) + sizeof(uint8_t);
	set_kexinit_msg(data_packet + shift, name_list);
	wrap_message(data_packet, packet_size, msg_size, 0);

	append(data_packet + shift, msg_size, STRING_T);
	
	printf("Expecting the SSH_MSG_KEXINIT message from the server\n");
	if ((numbytes = recv(network_socket, server_response, 
						MAX_BUF_SIZE, 0)) == -1) {
		print_error("cannot receive the SSH_MSG_KEXINIT message");
		free(data_packet);
		close(network_socket);
		exit(EXIT_FAILURE);
	}
	if (numbytes == 0) {
		print_error("the server has closed the connection");
		free(data_packet);
		close(network_socket);
		exit(EXIT_FAILURE);
	}
	printf("The SSH_MSG_KEXINIT message is received\n");

	length = ntohl(*(uint32_t *) (server_response))
			 - server_response[sizeof(uint32_t)] - sizeof(uint8_t);
	shift = sizeof(uint32_t) + sizeof(uint8_t);
	append(server_response + shift, length, STRING_T);

	printf("Sending the SSH_MSG_KEXINIT message to server\n");
	if (send(network_socket, data_packet, packet_size, 0) == -1) {
		print_error("cannot send the SSH_MSG_KEXINIT message");
		free(data_packet);
		close(network_socket);
		exit(EXIT_FAILURE);		
	}
	printf("The SSH_MSG_KEXINIT message is sent\n");
 
	free(data_packet);
}

size_t get_kexdh_init_msg_size(uint8_t e[DH_MPINT_SIZE])
{
	size_t size;

	size = sizeof(uint8_t) + sizeof(uint32_t) + DH_MPINT_SIZE;

	/* 
	 * If the most significant bit would be equal to one for a 
	 * positive number, the number must be preceded by a zero
	 * byte.
	 */
	if (e[0] & 0x80)
		size += 1;

	return size;
}

#define SSH_MSG_KEXDH_INIT 30

void set_kexdh_init_msg(uint8_t *data, uint8_t e[DH_MPINT_SIZE])
{
	int length, shift = 0;

	data[shift++] = SSH_MSG_KEXDH_INIT;
	length = DH_MPINT_SIZE;

	/* 
	 * If the most significant bit would be equal to one for a 
	 * positive number, the number must be preceded by a zero
	 * byte.
	 */
	if (e[0] & 0x80)
		length += 1;

	*(uint32_t *) (data + shift) = htonl(length);
	shift += sizeof(uint32_t);

	if (e[0] & 0x80)
		data[shift++] = 0;

	memcpy(data + shift, e, DH_MPINT_SIZE);
}

void exchange_keys(int network_socket)
{
	int i, numbytes, shift;
	uint8_t server_response[MAX_BUF_SIZE];
	uint8_t DH_x[DH_MPINT_SIZE], DH_e[DH_MPINT_SIZE], DH_f[DH_MPINT_SIZE];
	uint8_t RSA_s[RSA_MPINT_SIZE], RSA_n[RSA_MPINT_SIZE],
					 RSA_e[RSA_MPINT_SIZE] = {0};
	uint32_t length;
	SHA1Context sha;
	uint8_t fingerprint[SHA1HashSize];

	DH_generate_x(DH_x);
	DH_compute_e(DH_e, DH_x);

	size_t msg_size = get_kexdh_init_msg_size(DH_e);
	size_t packet_size = get_packet_size(msg_size, 0, 0);
	uint8_t *data_packet = (uint8_t *) calloc(packet_size, 
							sizeof(uint8_t));

	shift = sizeof(uint32_t) + sizeof(uint8_t);
	set_kexdh_init_msg(data_packet + shift, DH_e);
	wrap_message(data_packet, packet_size, msg_size, 0);
	
	printf("Sending the SSH_MSG_KEXDH_INIT message to server\n");
	if (send(network_socket, data_packet, packet_size, 0) == -1) {
		print_error("cannot send the SSH_MSG_KEXDH_INIT message");
		free(data_packet);
		close(network_socket);
		exit(EXIT_FAILURE);		
	}
	printf("The SSH_MSG_KEXDH_INIT message is sent\n");

	printf("Expecting the SSH_MSG_KEXDH_REPLY message from the server\n");
	if ((numbytes = recv(network_socket, server_response,
						 sizeof(length), 0)) == -1) {
		print_error("cannot receive the SSH_MSG_KEXDH_REPLY message");
		free(data_packet);
		close(network_socket);
		exit(EXIT_FAILURE);
	}
	if (numbytes == 0) {
		print_error("the server has closed the connection");
		free(data_packet);
		close(network_socket);
		exit(EXIT_FAILURE);
	}
	length = ntohl(*((uint32_t *) server_response));
	shift = sizeof(length);
	numbytes += recv(network_socket, server_response + shift, 
							length, 0);
	printf("The SSH_MSG_KEXDH_REPLY message is received\n");
	
	/* extract K_S */
	shift = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t);
	length = ntohl(*(uint32_t *) (server_response + shift));
	shift += sizeof(uint32_t);
	append(server_response + shift, length, STRING_T);

	printf("Server public key fingerprint:\n\t");
	SHA1Reset(&sha);
	SHA1Input(&sha, server_response + shift, length);
	SHA1Result(&sha, fingerprint);
	for (i = 0; i < SHA1HashSize - 1; ++i)
		printf("%02x:", fingerprint[i]);
	printf("%02x\n", fingerprint[i]);

	/* extract (e, n) */
	length = ntohl(*(uint32_t *) (server_response + shift));
	shift += sizeof(uint32_t) + length;
	length = ntohl(*(uint32_t *) (server_response + shift));
	shift += sizeof(uint32_t);
	for (i = 0; i < length; ++i)
		RSA_e[RSA_MPINT_SIZE - length + i] =
						 server_response[shift + i];
	shift += length;
	length = ntohl(*(uint32_t *) (server_response + shift));
	shift += sizeof(uint32_t);
	if (server_response[shift] == 0x00) {
		shift++;
		memcpy(RSA_n, server_response + shift, RSA_MPINT_SIZE);
		shift--;
	} else {
		memcpy(RSA_n, server_response + shift, RSA_MPINT_SIZE);
	}

	append(DH_e, sizeof(DH_e), MPINT_T);

	/* extract f */
	shift += length;
	length = ntohl(*(uint32_t *) (server_response + shift));
	shift += sizeof(uint32_t);
	if (server_response[shift] == 0x00) {
		shift++;
		memcpy(DH_f, server_response + shift, DH_MPINT_SIZE);
		append(server_response + shift, DH_MPINT_SIZE, MPINT_T);
		shift--;
	} else {
		memcpy(DH_f, server_response + shift, DH_MPINT_SIZE);
		append(server_response + shift, DH_MPINT_SIZE, MPINT_T);
	}

	/* extract signature */
	shift += length;
	shift += sizeof(uint32_t);
	length = ntohl(*(uint32_t *) (server_response + shift));
	shift += sizeof(uint32_t) + length;
	shift += sizeof(uint32_t);
	memcpy(RSA_s, server_response + shift, RSA_MPINT_SIZE);

	DH_compute_K(K, DH_f, DH_x);
	append(K, sizeof(K), MPINT_T);

	printf("Verifying the signature: ");
	SHA1Reset(&sha);
	SHA1Input(&sha, pre_hash, pre_hash_size);
	SHA1Result(&sha, H);
	if (RSA_verify(H, sizeof(H), RSA_s, RSA_e, RSA_n))
		printf("invalid\n");
	else
		printf("valid\n");

	free(data_packet);
}

void derive_keys()
{
	SHA1Context sha;
	char letter = 'A';
	int shift;

	append(K, sizeof(K), MPINT_T);
	append(H, sizeof(H), RAW_T);
	append((uint8_t *) &letter, sizeof(letter), RAW_T);
	append(session_id, sizeof(session_id), RAW_T);

	shift = pre_hash_size - sizeof(session_id) - sizeof(letter);

	/* derive IV_ctos */
	SHA1Reset(&sha);
	SHA1Input(&sha, pre_hash, pre_hash_size);
	SHA1Result(&sha, IV_ctos);

	/* derive IV_stoc */
	(*(pre_hash + shift))++;
	SHA1Reset(&sha);
	SHA1Input(&sha, pre_hash, pre_hash_size);
	SHA1Result(&sha, IV_stoc);

	/* derive encryption_k_ctos */
	(*(pre_hash + shift))++;
	SHA1Reset(&sha);
	SHA1Input(&sha, pre_hash, pre_hash_size);
	SHA1Result(&sha, encryption_k_ctos);

	/* derive encryption_k_stoc */
	(*(pre_hash + shift))++;
	SHA1Reset(&sha);
	SHA1Input(&sha, pre_hash, pre_hash_size);
	SHA1Result(&sha, encryption_k_stoc);

	/* derive integrity_k_ctos */
	(*(pre_hash + shift))++;
	SHA1Reset(&sha);
	SHA1Input(&sha, pre_hash, pre_hash_size);
	SHA1Result(&sha, integrity_k_ctos);

	/* derive integrity_k_stoc */
	(*(pre_hash + shift))++;
	SHA1Reset(&sha);
	SHA1Input(&sha, pre_hash, pre_hash_size);
	SHA1Result(&sha, integrity_k_stoc);
}

int main(int argc, char *argv[])
{
	char *address = "205.166.94.15";
	int network_socket;

	prog_name = argv[0];

	network_socket = initialize_connection(address);

	pre_hash_size = 0;
	exchange_protocol_versions(network_socket);
	negotiate_algorithms(network_socket);
	exchange_keys(network_socket);

	pre_hash = (uint8_t *) realloc(pre_hash, 0);
	pre_hash_size = 0;
	memcpy(session_id, H, SHA1HashSize);
	derive_keys();

	shutdown(network_socket, SHUT_RDWR);
	close(network_socket);

	return EXIT_SUCCESS;
}
