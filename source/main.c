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

#define SSH_PORT 22

char *prog_name;

void print_error(const char *str)
{
	fprintf(stderr, "%s: %s", prog_name, str);
	if (errno)
		fprintf(stderr, ": %s", strerror(errno));
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
	char identification_string[] = "SSH-2.0-OpenSSH_7.1\r\n";
	char server_response[MAX_BUF_SIZE];
	int numbytes;

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

int main(int argc, char *argv[])
{
	char *address = "205.166.94.15";
	int network_socket;

	prog_name = argv[0];

	network_socket = initialize_connection(address);

	exchange_protocol_versions(network_socket);
	negotiate_algorithms(network_socket);

	shutdown(network_socket, SHUT_RDWR);
	close(network_socket);

	return EXIT_SUCCESS;
}
