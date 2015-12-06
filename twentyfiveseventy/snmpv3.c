#include <stdio.h>
#include <strings.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include "proto.h"

mib MIB[MAX_MIBS];
extern uint32_t msgAuthoritativeEngineBoots;
extern uint32_t myAuthoritativeEngineTime;
extern unsigned char AUTH_PASSPHRASE[MAX_PASSPHRASE_LEN];
extern unsigned char PRIV_PASSPHRASE[MAX_PASSPHRASE_LEN];
extern uint32_t FAIL_COUNT;

uint8_t ReceivePacket(unsigned char *pkt) {
	unsigned int len;
	unsigned int msg_len;
	unsigned int read_len;
	unsigned int len_bytes;

	if ((len = read(0, pkt, 2)) <= 0) {
		return(ERROR_GENERR);
	}

	// make sure we got 2 bytes
	if (len != 2) {
		return(ERROR_GENERR);
	}

	// should begin with a sequence
	if (pkt[0] != SEQUENCE) {
		return(ERROR_BADVALUE);
	}

	// next, check the length
	len_bytes = 0;
	if (pkt[1] & 0x80) {
		// got a pkt larger than 0x7f
		// see how many bytes we need to read to 
		// obtain the actual msg length
		len_bytes = pkt[1] & 0x7f;

		if ((len = read(0, pkt+2, len_bytes)) <= 0) {
			return(ERROR_GENERR);
		}

		if (len != len_bytes) {
			return(ERROR_GENERR);
		}

		msg_len = ParseLen(pkt+2, len_bytes);
		if (msg_len > MAX_PKT_LEN) {
			return(ERROR_TOOBIG);
		}
	} else {
		msg_len = pkt[1];
	}

	// read in the rest of the packet
	read_len = 0;
	while (read_len < msg_len) {
		if ((len = read(0, pkt+2+len_bytes+read_len, msg_len-read_len)) <= 0) {
			return(ERROR_GENERR);
		}

		if (len == 0) {
			return(ERROR_GENERR);
		}

		read_len += len;
	}

	return(ERROR_NOERROR);
}

int InitMIB(void) {
	FILE *in;
	char flag[100];

	bzero(flag, 100);
	if ((in = fopen("/home/twentyfiveseventy/flag", "r")) == NULL) {
		fprintf(stderr, "oh shit, the flag file isn't present\n");
		return(-1);
	}
	fread(flag, 1, 99, in);
	fclose(in);

	memcpy(MIB[0].OID_str, "\x2b\x06\x01\x02\x01\x01\x05\x00", 8);
	MIB[0].OID_len = 8;
	MIB[0].type = OCTET_STRING;
	if ((MIB[0].value = calloc(1,strlen(flag))) == NULL) {
		return(-1);
	}
	strcpy(MIB[0].value, flag);
	MIB[0].len = strlen(flag);

	return(0);
}

void DestroyMIB(void) {
	int i;

	for (i = 0; i < MAX_MIBS; i++) {
		if (MIB[i].value) {
			free(MIB[i].value);
			MIB[i].value = NULL;
		}
	}

}

int InitCreds(void) {
	time_t t;
	int i;
	FILE *in;

	// get the current time
	t = time(NULL);

	// use time to seed the PRNG
	srand(t);

	// set the EngineTime using that same time value (leaking the PRNG seed)
	myAuthoritativeEngineTime = t;
	
	// set the EngineBoots
	msgAuthoritativeEngineBoots = rand() % 128;

	// read in the auth passphrase
	if ((in = fopen("/home/twentyfiveseventy/auth_passphrase", "r")) == NULL) {
		fprintf(stderr, "damn, the auth_passphrase file is missing\n");
		return(-1);
	}
	bzero(AUTH_PASSPHRASE, MAX_PASSPHRASE_LEN);
	fread(AUTH_PASSPHRASE, 1, MAX_PASSPHRASE_LEN-1, in);
	fclose(in);

	// init the priv passphrase
	bzero(PRIV_PASSPHRASE, MAX_PASSPHRASE_LEN);
	for (i = 0; i < MAX_PASSPHRASE_LEN; i++) {
		PRIV_PASSPHRASE[i] = (rand() % (0x7e - 0x20)) + 0x20;
	}

	return(0);

}

void tooslow(int sig) {
        exit(-1);
}

int main(void) {
	unsigned char pkt[MAX_PKT_LEN];
	request req;
	uint8_t retval;

	// keep track of how many request failures we see
	FAIL_COUNT = 0;

	if (InitMIB()) {
		return(-1);
	}

	if (InitCreds()) {
		return(-1);
	}


        signal(SIGALRM, tooslow);
        alarm(TIMEOUT);

	while (1) {
		if (FAIL_COUNT > MAX_FAIL_COUNT) {
			exit(-1);
		}
		bzero(pkt, MAX_PKT_LEN);
		bzero(&req, sizeof(request));

		if (ReceivePacket(pkt) != ERROR_NOERROR) {
			DestroyMIB();
			exit(-1);
		}
        	alarm(TIMEOUT);

		if ((retval = ParsePacket(pkt, &req)) != ERROR_NOERROR) {
			FAIL_COUNT++;
			if (retval != ERROR_SILENTFAIL) {
				req.ErrorStatus = retval;
				SendReport(&req);
			}
			if (retval != ERROR_NOACCESS) {
				DestroyMIB();
				exit(-1);
			}

			continue;
		}

		// based on the SNMP message flags, perform different tasks
		if (req.reportable && !(req.authenticated || req.encrypted)) {
			// send a Discovery report
			if (SendReport(&req) != ERROR_NOERROR) {
				exit(-1);
			}
		} else if (req.authenticated && req.encrypted) {
			// handle any Get requests
			if ((retval = HandleRequest(&req)) != ERROR_NOERROR) {
				FAIL_COUNT++;
				if (retval != ERROR_SILENTFAIL) {
					req.ErrorStatus = retval;
					SendReport(&req);
				}
			}
			
			if ((retval = SendResponse(&req)) != ERROR_NOERROR) {
				FAIL_COUNT++;
				if (retval != ERROR_SILENTFAIL) {
					req.ErrorStatus = retval;
					SendReport(&req);
				}
			}
		} else {
			// treat all others as failures
			FAIL_COUNT++;
		}
	}
}
