#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define BUFFSZ 4010

int  send_query(SOCKET sd, struct sockaddr_in *peer, uint8_t *input, int inputsz, uint8_t *output, int outputsz);
void handle_source(uint8_t *packet, int bytes);

int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("%s [ip] [port]\n", argv[0]);
		return 1;
	}
	
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(1,0), &wsadata) != 0) {
		printf("wsastartup failed\n");
		return 1;
	}
	
	int bytes;
	SOCKET 	sd;
	uint8_t buff[BUFFSZ+1];
	struct  sockaddr_in peer;
	uint8_t query[] = "\xff\xff\xff\xffTSource Engine Query\0";
	char    tip_buff[16];
	
	sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sd < 0) {
		printf("socket: %d\n", WSAGetLastError());
		WSACleanup();
		exit(1);
	}
	
	peer.sin_family = AF_INET;
	peer.sin_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &peer.sin_addr) <= 0) {
		printf("inet_pton: %d\n", WSAGetLastError());
		closesocket(sd);
		WSACleanup();
		exit(1);
	}
	inet_ntop(AF_INET, &peer.sin_addr, tip_buff, sizeof(tip_buff));
	printf("\nconnected to %s\n\n", tip_buff);
	
	bytes = send_query(sd, &peer, query, sizeof(query), buff, BUFFSZ);
	handle_source(buff, bytes);
	
	closesocket(sd);
	WSACleanup();
	return 0;
}

int send_query(SOCKET sd, struct sockaddr_in *peer, uint8_t *input, int inputsz, uint8_t *output, int outputsz) {
	int bytes;
	DWORD timeout = 1000;
	
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)); //set timeout to 1s
	
	bytes = sendto(sd, input, inputsz, 0, (struct sockaddr *)peer, sizeof(*peer)); //send source query
	if (bytes == SOCKET_ERROR) {
		printf("sendto: %d\n", WSAGetLastError());
		exit(1);
	}
	
	bytes = recvfrom(sd, output, outputsz, 0, NULL, NULL); //recieve packet
	if (bytes == SOCKET_ERROR) {
		printf("recvfrom: %d\n", WSAGetLastError());
		exit(1);
	}
}

void handle_source(uint8_t *packet, int bytes) {
	printf("raw hex dump:\n");
	
	for (int i = 0; i < bytes; i++)
		printf("%02x ", packet[i]);
	
	printf("\n\n");
	
	packet += 6; //skip signature bytes
	printf("%20s: %s\n",      "hostname", 	    packet);                packet += strlen(packet) + 1; //move to next entry
	printf("%20s: %s\n",      "map",      	    packet);                packet += strlen(packet) + 1;
	printf("%20s: %s\n",      "mod",      	    packet);                packet += strlen(packet) + 1;
	printf("%20s: %s\n",      "desc",     	    packet);                packet += strlen(packet) + 3;
	printf("%20s: %u/%u\n",   "players", 	   *packet, *(packet + 1)); packet += 2;
	printf("%20s: %u\n",      "bots",          *packet);                packet++;
	printf("%20s: %c\n",      "server type",   *packet);                packet++;
	printf("%20s: %c\n",      "server os",     *packet);                packet++;
	printf("%20s: %u\n",      "password",      *packet);                packet++;
	printf("%20s: %u\n",      "secure server", *packet);
}