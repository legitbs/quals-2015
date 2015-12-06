#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include "common.h"

unsigned int alarm_count;
time_t mytime = 0;
struct sockaddr_in tardis;
struct _s {
	char buf[8];
	int sockfd;
};
struct _s s;
int TardisOnline;
#define PASSWD_LEN 10
#define UPDATE_INTERVAL 2
#define END_GAME (1431907200)
#define SECONDS_BEFORE (20)
#define MAX_IDLE 5

void AngelGame(void);

void UpdateTime(int signum) {
	time_t resp;
	ssize_t n;

	if (alarm_count++ > MAX_IDLE) {
		printf("\nUnauthorized occupant detected...goodbye\n");
		exit(-1);
	}

	if (s.sockfd != -1) {
		write(s.sockfd, "\x00", 1);
		n = read(s.sockfd, &resp, 4);
		if (n == 4) {
			mytime = resp;
		} 
		// reset the alarm for the next interval
		alarm(UPDATE_INTERVAL);
	} else {
		fprintf(stderr, "Time vortex not responding\n");
	}
}

int SetupSocket(void) {
	struct timeval tv;

	if ((s.sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("oh shit...failed to create socket\n");
		exit(-1);
	}

	tv.tv_sec = 0;
	tv.tv_usec = 1000;
	if (setsockopt(s.sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		printf("setsockopt failed\n");
		close(s.sockfd);
		exit(-1);
	}

	bzero(&tardis, sizeof(tardis));
	tardis.sin_family = AF_INET;
	tardis.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	tardis.sin_port = htons(TARDIS_KEY);

	// connect the UDP socket, so we can use read/write calls to interact with it
	if (connect(s.sockfd, (struct sockaddr *)&tardis, sizeof(tardis)) != 0) {
		printf("connect failed\n");
	}

	return(0);

}

int IsTimelockOpen(void) {
	if (mytime > END_GAME-SECONDS_BEFORE && mytime < END_GAME) {
		return(1);
	}
	return(0);
}

void PrintMenu(void) {
	printf("Your options are: \n");
	printf("1. Turn on the console\n");
	printf("2. Leave the TARDIS\n");
	if (TardisOnline) {
		printf("3. Dematerialize\n");
	}
	printf("Selection: ");
	fflush(stdout);
}

int KeyCheck(void) {
	char buf;
	int i = PASSWD_LEN;
	char *p;
	char c;

	printf("TARDIS KEY: ");
	fflush(stdout);

	p = (char *)KeyCheck;
	while (i) {
		if (isalnum((*p & 0x7f))) {
			if (read(0, &buf, 1) == 1) {
				if (buf != (*p & 0x7f)) {
					return(1);
				}
			}

			i--;
		}
		p++;
	}
	while ((c = getchar()) != '\n' && c != EOF);

	return(0);
}

int read_until(int fd, char *buf, int max, char delim) {
	int total_len = 0;
	char c;
	ssize_t len;

	while (total_len < max) {
		if ((len = read(fd, &c, 1)) <= 0) {
			return(-1);
		}
		if (len == 0) {
			return(-1);
		}
		if (c == delim) {
			buf[total_len] = '\0';
			return(total_len);
		}
		buf[total_len++] = c;
	}

	buf[total_len-1] = '\0';
	return(total_len-1);
}

int Dematerialize(void) {
	char buf[1024];
	double longitude, latitude;
	char *lat;

	while (1) {
		printf("Coordinates: ");
		fflush(stdout);

		// read in the coordinates
		if (read_until(0, buf, 1023, '\n') == -1) {
			exit(-1);
		}

		if ((lat = strchr(buf, ',')) == NULL) {
			printf("Invalid coordinates\n");
			continue;
		}

		lat++;
		longitude = atof(buf);
		latitude = atof(lat);

		printf("%f, %f\n", longitude, latitude);
		// see if they match 51.492137,-0.192878
		if (longitude == 51.492137 && latitude == -0.192878) {
			printf("Coordinate ");
			printf(buf);
			printf(" is occupied by another TARDIS.  Materializing there ");
			printf("would rip a hole in time and space. Choose again.\n");
			fflush(stdout);
			continue;
		} else {
			// otherwise, let's go there
			printf("You safely travel to coordinates %s\n", buf);
			fflush(stdout);
			break;
		}
		
	}

}

int main(int argc, char **argv) {
	int res;
	struct tm *tm;
	char start_str[100];
	char end_str[100];
	time_t sec = END_GAME - SECONDS_BEFORE;

	s.sockfd = -1;
	TardisOnline = 0;

	// first, play the game
	AngelGame();

	// Found the TARDIS, but do you have the key?
	if (KeyCheck()) {
		printf("Wrong key!\n");
		printf("Enjoy 1960...\n");
		return(0);
	}
	printf("Welcome to the TARDIS!\n");

	// build the string for when the time lock is removed
	sec = END_GAME - SECONDS_BEFORE;
	tm = gmtime(&sec);
	strftime(start_str, 99, "%b %d %Y %H:%M:%S %Z", tm);
	sec = END_GAME;
	tm = gmtime(&sec);
	strftime(end_str, 99, "%b %d %Y %H:%M:%S %Z", tm);

	// set up the socket for the time update
	SetupSocket();
	UpdateTime(0);
 
	// set a signal to update mytime periodically
        signal(SIGALRM, UpdateTime);
	alarm(UPDATE_INTERVAL);

	while (1) {
		alarm_count = 0;
		PrintMenu();
		bzero(s.buf, 8);
		if (read(0, s.buf, 9) <= 0) {
			exit(-1);
		}
		if (s.buf[0] == '1') {
			if (IsTimelockOpen()) {
				printf("The TARDIS console is online!");
				TardisOnline = 1;
				fflush(stdout);
			} else {
				printf("Access denied except between %s and %s\n", start_str, end_str);
				fflush(stdout);
			}
		} else if (s.buf[0] == '2') {
			printf("Enjoy 1960...\n");
			exit(0);
		} else if (s.buf[0] == '3') {
			if (!TardisOnline) {
				printf("Invalid\n");
				fflush(stdout);
			} else {
				// dematerialize
				Dematerialize();
			}
		} else {
			printf("Invalid\n");
			fflush(stdout);
		}

	}

	return(0);
}
