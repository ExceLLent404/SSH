#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SSH_PORT 20
#define MAX_BUF_SIZE 100

int main(int argc, char *argv[])
{
	char *address, *prog_name = argv[0];
	int network_socket;
	int conversion_status, numbytes;
	struct sockaddr_in server_address;
	char request[] = "SSH-2.0-OpenSSH_7.1\r\n";
	char server_response[MAX_BUF_SIZE];

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <IPv4 address>\n", prog_name);
		exit(EXIT_FAILURE);
	}

	address = argv[1];

	if ((network_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "%s: cannot create socket: %s",
						 prog_name, strerror(errno));
		close(network_socket);
		exit(EXIT_FAILURE);
	}

	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(22);
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

	if (send(network_socket, request, strlen(request), 0) == -1) {
		fprintf(stderr, "%s: cannot send data: %s",
						 prog_name, strerror(errno));
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

	shutdown(network_socket, SHUT_RDWR);
	close(network_socket);

	return EXIT_SUCCESS;
}
