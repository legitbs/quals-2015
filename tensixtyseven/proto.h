#ifndef PROTO_H
#define PROTO_H

#define PRIV_COMM_LEN 8

#define TYPE_INTEGER (0x02)
#define TYPE_OCTETSTRING (0x04)
#define TYPE_NULL (0x05)
#define TYPE_OID (0x06)
#define TYPE_SEQUENCE (0x30)
#define GET_REQUEST (0xA0)
#define GET_NEXT_REQUEST (0xA1)
#define GET_RESPONSE (0xA2)
#define SET_REQUEST (0xA3)
#define TL_LEN (2)

#define ERROR_NOERROR (0x00)
#define ERROR_TOOLARGE (0x01)
#define ERROR_NOTFOUND (0x02)
#define ERROR_BADTYPE (0x03)
#define ERROR_SETRO (0x04)
#define ERROR_GENERAL (0x05)

#define MAX_SET_PER_SESSION 5
#define MAX_ERRORS 5

// Authenticate return values
#define AUTH_DENIED (0)
#define AUTH_READ (1)
#define AUTH_WRITE (2)

typedef struct _tlv {
	uint8_t type;
	uint8_t len;
	void *value;
} tlv;

typedef struct _req {
	uint8_t version;
	char *community;
	uint8_t community_len;
	uint8_t type;
	uint32_t request_id;
	tlv oid[255];
	tlv value[255];
	uint8_t count;
	uint8_t error;
	uint8_t error_index;
} req;


int ParseSnmpPkt(unsigned char *, ssize_t, req *);
void PrintRequest(req *);
void DestroyRequest(req *);
void SendResponse(req *);
void HandleGetRequest(req *);
void HandleGetNextRequest(req *);
void HandleSetRequest(req *);
int CreateNewOID(req *, uint8_t, req *, tlv *);

#endif
