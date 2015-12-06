#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <signal.h>
#include "proto.h"
#include "tree.h"

// TODO, changeme
#define TIMEOUT (5)

// community strings
unsigned char *public_comm;
unsigned char *private_comm;

extern tlv *MIB;
extern uint8_t SetCount;
extern uint8_t ErrCount;

// generate a random string of specified length
void RndStr(unsigned char *s, uint8_t len) {
	uint8_t i;
	uint8_t rnd;

	for (i = 0; i < len; i++) {
		rnd = (rand() % ('~' - ' ')) + 0x20;
		s[i] = rnd;	
	}
}

void PopulateMIB(void) {
	tlv data;
	unsigned char oid[256];
	tree *leaf;
	int i;

	public_comm = calloc(1,6);
	memcpy(public_comm, "public", 6);

	private_comm = calloc(1,PRIV_COMM_LEN);
	RndStr(private_comm, PRIV_COMM_LEN);

	//
	// public access
	//
	oid[0] = 0x2b;
	oid[1] = 6;
	oid[2] = 1;
	oid[3] = 6;
	oid[4] = 3;
	oid[5] = 18; // snmpCommunityMIB
	oid[6] = 1;  // snmpCommunityMIBObjects
	oid[7] = 1;  // snmpCommunityTable
	oid[8] = 1;  // snmpCommunityEntry
	oid[9] = 1;  // snmpCommunityIndex
	oid[10] = 2; // snmpCommunityName
	data.type = TYPE_OCTETSTRING;
	data.len = 6;
	data.value = public_comm;
	if (InsertLeaf(oid, 11, &data, NULL, 0) == NULL) {
		fprintf(stderr, "Failed to insert leaf\n");
		exit(-1);
	}

	oid[0] = 0x2b;
	oid[1] = 6;
	oid[2] = 1;
	oid[3] = 6;
	oid[4] = 3;
	oid[5] = 18; // snmpCommunityMIB
	oid[6] = 1;  // snmpCommunityMIBObjects
	oid[7] = 1;  // snmpCommunityTable
	oid[8] = 1;  // snmpCommunityEntry
	oid[9] = 1;  // snmpCommunityIndex
	oid[10] = 8; // snmpCommunityStatus
	data.type = TYPE_INTEGER;
	data.len = 1;
	data.value = calloc(1, 1);
	*((uint8_t *)(data.value)) = 2;
	if (InsertLeaf(oid, 11, &data, NULL, 0) == NULL) {
		fprintf(stderr, "Failed to insert leaf\n");
		exit(-1);
	}

	//
	// 'private' access
	//
	oid[0] = 0x2b;
	oid[1] = 6;
	oid[2] = 1;
	oid[3] = 6;
	oid[4] = 3;
	oid[5] = 18; // snmpCommunityMIB
	oid[6] = 1;  // snmpCommunityMIBObjects
	oid[7] = 1;  // snmpCommunityTable
	oid[8] = 1;  // snmpCommunityEntry
	oid[9] = 2;  // snmpCommunityIndex
	oid[10] = 2; // snmpCommunityName
	data.type = TYPE_OCTETSTRING;
	data.len = PRIV_COMM_LEN;
	data.value = private_comm;
	if ((leaf = InsertLeaf(oid, 11, &data, NULL, 0)) == NULL) {
		fprintf(stderr, "Failed to insert leaf\n");
		exit(-1);
	}
	leaf->auth = &(leaf->data);

	oid[0] = 0x2b;
	oid[1] = 6;
	oid[2] = 1;
	oid[3] = 6;
	oid[4] = 3;
	oid[5] = 18; // snmpCommunityMIB
	oid[6] = 1;  // snmpCommunityMIBObjects
	oid[7] = 1;  // snmpCommunityTable
	oid[8] = 1;  // snmpCommunityEntry
	oid[9] = 2;  // snmpCommunityIndex
	oid[10] = 8; // snmpCommunityStatus
	data.type = TYPE_INTEGER;
	data.len = 1;
	data.value = calloc(1, 1);
	*((uint8_t *)(data.value)) = 2;
	if (InsertLeaf(oid, 11, &data, leaf->auth, 0) == NULL) {
		fprintf(stderr, "Failed to insert leaf\n");
		exit(-1);
	}

	oid[0] = 0x2b;
	oid[1] = 8;
	oid[2] = 10;
	data.type = TYPE_INTEGER;
	data.len = 1;
	data.value = calloc(1, 1);
	*(uint8_t *)data.value = 1;
	if (InsertLeaf(oid, 3, &data, NULL, 0) == NULL) {
		fprintf(stderr, "Failed to insert leaf\n");
		exit(-1);
	}

	// BUG leak stack address
	oid[0] = 0x2b;
	oid[1] = 8;
	oid[2] = 0x8A;
	oid[3] = 0x39;
	data.type = TYPE_OCTETSTRING;
	data.len = 8;
	data.value = calloc(1, 8);
	*(uint64_t *)data.value = (uint64_t)&leaf ^ 0xdeadbeefcafebabe;
	if (InsertLeaf(oid, 4, &data, NULL, 0) == NULL) {
		fprintf(stderr, "Failed to insert leaf\n");
		exit(-1);
	}

}

void tooslow(int sig) {
	exit(-1);
}

uint8_t ReceivePacket(unsigned char *pkt, uint8_t max_len) {
	uint8_t total_received;
	ssize_t len;

	if (pkt == NULL) {
		return(0);
	}

	if ((len = read(0, pkt, 2)) <= 0) {
		return(0);
	}
	if (len != 2) {
		return(0);
	}

	if (pkt[0] != TYPE_SEQUENCE || pkt[1] > 0x7f || pkt[1] > max_len) {
		return(0);
	}

	total_received = 0;
	while (total_received < pkt[1]) {
		if ((len = read(0, pkt+2+total_received, pkt[1]-total_received)) <= 0) {
			return(0);
		}
		total_received += len;
	}
	total_received+=TL_LEN;

	return(total_received);
}

int main(void) {
	unsigned char pkt[200];
	req r;
	ssize_t len;
	unsigned int i;
	FILE *in;
	uint32_t seed;

	signal(SIGALRM, tooslow);
	alarm(TIMEOUT);

	// set up the head of the SNMP MIB tree
	InitTree();
	SetCount = 0;
	ErrCount = 0;

	// seed the prng
	if ((in = fopen("/dev/urandom", "r")) == NULL) {
		exit(-1);
	}
	if (fread(&seed, 1, 4, in) != 4) {
		exit(-1);
	}
	fclose(in);
	srand(seed);

	// init the MIB with some objects
	PopulateMIB();

	while (1) {
		if (ErrCount > MAX_ERRORS) {
			DestroyTree(MIB);
			exit(-1);
		}
		bzero(pkt, 200);
		bzero(&r, sizeof(req));

		if ((len = ReceivePacket(pkt, 200)) == 0) {
			DestroyTree(MIB);
			exit(-1);
		}

		// reset the timer
		alarm(TIMEOUT);
		
		// parse the packet and handle the particular request
		if (ParseSnmpPkt(pkt, len, &r)) {
			if (r.type == GET_REQUEST) {
				HandleGetRequest(&r);
			} else if (r.type == GET_NEXT_REQUEST) {
				HandleGetNextRequest(&r);
			} else if (r.type == SET_REQUEST) {
				HandleSetRequest(&r);
			}
		} else {
			// error parsing packet
			ErrCount++;
		}
	}
}
