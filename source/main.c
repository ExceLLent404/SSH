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

#define SSH_PORT 22
#define MAX_BUF_SIZE 1024

/* Returns a new socket descriptor */
int initialize_connection(char *address, char *prog_name)
{
	int network_socket;
	int conversion_status;
	struct sockaddr_in server_address;

	if ((network_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "%s: cannot create socket: %s",
						 prog_name, strerror(errno));
		close(network_socket);
		exit(EXIT_FAILURE);
	}

	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(SSH_PORT);
	if ((conversion_status = inet_pton(AF_INET, address,
					 &server_address.sin_addr)) == -1) {
		fprintf(stderr, "%s: address conversion failed: %s",
						 prog_name, strerror(errno));
		close(network_socket);
		exit(EXIT_FAILURE);
	} else if (!conversion_status) {
		fprintf(stderr, "%s: input isn't a valid IP address\n",
								 prog_name);
		close(network_socket);
		exit(EXIT_FAILURE);
	}

	printf("Connecting to %s\n", address);
	if (connect(network_socket, (struct sockaddr *) &server_address,
		 			sizeof(server_address)) == -1) {
		fprintf(stderr, "%s: connection failed: %s",
						 prog_name, strerror(errno));
		close(network_socket);
		exit(EXIT_FAILURE);
	}

	return network_socket;
}

void protocol_version_exchange(int network_socket, char *prog_name)
{
	char identification_string[] = "SSH-2.0-OpenSSH_7.1\r\n";
	char server_response[MAX_BUF_SIZE];
	int numbytes;

	printf("Sending the identification string: %s", identification_string);
	if (send(network_socket, identification_string, 
				strlen(identification_string), 0) == -1) {
		fprintf(stderr, "%s: cannot send the identification "
				"string: %s", prog_name, strerror(errno));
		close(network_socket);
		exit(EXIT_FAILURE);		
	}
	if ((numbytes = recv(network_socket, server_response, 
						MAX_BUF_SIZE - 1, 0)) == -1) {
		fprintf(stderr, "%s: cannot receive data: %s",
						 prog_name, strerror(errno));
		close(network_socket);
		exit(EXIT_FAILURE);
	}
	if (numbytes == 0) {
		fprintf(stderr, "%s: the server has closed the connection",
								 prog_name);
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

size_t get_packet_size(size_t payload_size, size_t cipher_block_size, 
								int mac_length)
{
	int i, piece_size = (cipher_block_size > 8) ? cipher_block_size : 8;
	size_t packet_size, padding_length = 4;

	packet_size = sizeof(uint32_t) + sizeof(uint8_t) + payload_size;
	if ((packet_size + padding_length) % piece_size)
		padding_length += piece_size - 
				(packet_size + padding_length) % piece_size;
	packet_size += padding_length + mac_length;

	return packet_size;
}

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

int main(int argc, char *argv[])
{
	char *address, *prog_name = argv[0];
	int network_socket;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <IPv4 address>\n", prog_name);
		exit(EXIT_FAILURE);
	}

	address = argv[1];

	network_socket = initialize_connection(address, prog_name);

	protocol_version_exchange(network_socket, prog_name);

	shutdown(network_socket, SHUT_RDWR);
	close(network_socket);

	return EXIT_SUCCESS;
}
