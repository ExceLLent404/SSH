#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SSH_PORT 20

int main(int argc, char *argv[])
{
	char *address = argv[1];

	int network_socket;
	network_socket = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(22);
	inet_pton(AF_INET, address, &server_address.sin_addr);

	printf("Connecting to %s\n", address);
	connect(network_socket, (struct sockaddr *) &server_address,
		 				sizeof(server_address));

	char request[] = "SSH-2.0-OpenSSH_7.1\r\n";
	char server_response[4096];

	send(network_socket, request, sizeof(request), 0);
	recv(network_socket, &server_response, sizeof(server_response), 0);
	printf("The server sent the data:\n%s", server_response);

	shutdown(network_socket, SHUT_RDWR);
	close(network_socket);

	return 0;
}
