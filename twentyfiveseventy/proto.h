#ifndef PROTO_H
#define PROTO_H

// snmp types
#define INTEGER (0x02)
#define OCTET_STRING (0x04)
#define TYPE_NULL (0x05)
#define OID (0x06)
#define SEQUENCE (0x30)
#define COUNTER32 (0x41)
#define GET_REQUEST (0xA0)
#define GET_NEXT_REQUEST (0xA1)
#define GET_RESPONSE (0xA2)
#define SET_REQUEST (0xA3)
#define REPORT (0xA8)
#define USM (3)
#define SNMP_VERSION_3 (3)

// snmp errors
#define ERROR_NOERROR (0)
#define ERROR_TOOBIG (1)
#define ERROR_NOSUCHNAME (2)
#define ERROR_BADVALUE (3)
#define ERROR_READONLY (4)
#define ERROR_GENERR (5)
#define ERROR_NOACCESS (6)
#define ERROR_SILENTFAIL (255)

// flags
#define FLAG_REPORTABLE (0x4)
#define FLAG_ENCRYPTED (0x2)
#define FLAG_AUTHENTICATED (0x1)

// various limits
#define MAX_USERNAME_LEN (12)
#define MAX_AUTH_PARAM_LEN (12)
#define MAX_PRIV_PARAM_LEN (8)
#define MAX_OID_LEN (20)
#define MAX_CONTEXT_ENGINE_ID_LEN (12)
#define MAX_MIBS (1)
#define MAX_PASSPHRASE_LEN (32)
#define MAX_PKT_LEN (1500)
#define MAX_FAIL_COUNT (255)
#define TIMEOUT 5
#define VARIABLE_LEN (-1)
#define TL_LEN (2)

typedef struct _request {
	// headerData
	uint32_t msgID;
	bool reportable;
	bool encrypted;
	bool authenticated;

	// security headers
	unsigned char UserName[MAX_USERNAME_LEN];
	unsigned char AuthParam[MAX_AUTH_PARAM_LEN];
	uint32_t AuthParamLen;
	unsigned char PrivParam[MAX_PRIV_PARAM_LEN];
	uint32_t PrivParamLen;

	// PDUs
	unsigned char encryptedPDU[MAX_PKT_LEN];
	unsigned char plaintextPDU[MAX_PKT_LEN];
	uint32_t PDU_len;

	// parsed PDU data
	unsigned char contextEngineID[12];
	uint32_t requestID;
	unsigned char OID_str[MAX_OID_LEN];
	uint32_t OID_len;
	uint8_t ErrorStatus;

	// response data
	uint8_t type;
	uint8_t len;
	void *value;
} request;

// MIB to hold the flag
typedef struct _mib {
	unsigned char OID_str[MAX_OID_LEN];
	uint32_t OID_len;
	uint8_t type;
	uint8_t len;
	void *value;
} mib;

int ParsePacket(unsigned char *pkt, request *req);
uint8_t SendReport(request *);
uint8_t HandleRequest(request *);

#endif

