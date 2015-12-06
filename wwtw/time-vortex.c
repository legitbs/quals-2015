#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <strings.h>
#include "common.h"

int main(int argc, char **argv) {
	int sockfd,n;
	struct sockaddr_in tardis,caddr;
	socklen_t len;
	char req[1];
	time_t t;
	
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("failed to create the socket\n");
		return(-1);
	}

	bzero(&tardis, sizeof(tardis));
	tardis.sin_family = AF_INET;
	tardis.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	tardis.sin_port = htons(TARDIS_KEY);

	if (bind(sockfd,(struct sockaddr *)&tardis, sizeof(tardis)) != 0) {
		printf("failed to bind to port\n");
		close(sockfd);
		return(-1);
	}

	while (1) {
		len = sizeof(caddr);
		n = recvfrom(sockfd, req, 1, 0, (struct sockaddr *)&caddr, &len);
		t = time(NULL);
		sendto(sockfd, &t, 4, 0, (struct sockaddr *)&caddr, sizeof(caddr));
	}	

	close(sockfd);
	return(0);
}
