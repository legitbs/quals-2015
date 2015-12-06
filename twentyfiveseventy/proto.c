#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/hmac.h>
#include "proto.h"

unsigned char myAuthoritativeEngineID[] = "\x80\x00\x7a\x69\x03\xde\xad\xbe\xef\xca\xfe";
uint32_t myAuthoritativeEngineID_len = 11;
uint32_t msgAuthoritativeEngineBoots = 0;
uint32_t myAuthoritativeEngineTime = 0;
unsigned char USER[] = "lbs";
unsigned char AUTH_PASSPHRASE[MAX_PASSPHRASE_LEN];
unsigned char PRIV_PASSPHRASE[MAX_PASSPHRASE_LEN];
extern mib MIB[];
uint32_t SaltInt = 1209825;
uint32_t FAIL_COUNT = 0;

unsigned int ParseLen(unsigned char *p, unsigned int len) {
	unsigned int retval = 0;
	int i;

	if (len > 4) {
		return(0);
	}

	for (i = 0; i < len; i++) {
		retval += ((unsigned int)p[i]) << (len-i-1)*8;
	}

	return retval;
}

void password_to_key_md5(unsigned char *password, uint32_t passwordlen, unsigned char *engineID, uint32_t engineLength, unsigned char *key) {
	MD5_CTX MD;
	unsigned char *cp, password_buf[64];
	uint32_t password_index = 0;
	uint32_t count = 0, i;

	MD5_Init(&MD);

	while (count < 1048576) {
		cp = password_buf;
		for (i = 0; i < 64; i++) {
			*cp++ = password[password_index++ % passwordlen];
		}
		MD5_Update(&MD, password_buf, 64);
		count += 64;
	}
	MD5_Final(key, &MD);

	memcpy(password_buf, key, 16);	
	memcpy(password_buf+16, engineID, engineLength);
	memcpy(password_buf+16+engineLength, key, 16);

	MD5_Init(&MD);
	MD5_Update(&MD, password_buf, 32+engineLength);
	MD5_Final(key, &MD);

	return;
}

void DumpRequest(request *req) {
	uint32_t i;
	char *c;

	fprintf(stderr,"Request\n");
	fprintf(stderr,"  msgID: %d\n", req->msgID);
	fprintf(stderr,"  reportable: %s\n", req->reportable ? "true" : "false");
	fprintf(stderr,"  encrypted: %s\n", req->encrypted ? "true" : "false");
	fprintf(stderr,"  authenticated: %s\n", req->authenticated ? "true" : "false");
	fprintf(stderr,"  UserName: %s\n", req->UserName);
	fprintf(stderr,"  requestID: %d\n", req->requestID);
	fprintf(stderr,"  encryptedPDU: ");
	c = req->encryptedPDU;
	for (i = 0; i < req->PDU_len; i++) {
		fprintf(stderr, "%02x", (*c)&0xff);
		c++;
	}
	fprintf(stderr,"\n");
	fprintf(stderr,"  plaintextPDU: ");
	c = req->plaintextPDU;
	for (i = 0; i < req->PDU_len; i++) {
		fprintf(stderr, "%02x", (*c)&0xff);
		c++;
	}
	fprintf(stderr,"\n");
	fprintf(stderr,"  contextEngineID: ");
	c = req->contextEngineID;
	for (i = 0; i < MAX_CONTEXT_ENGINE_ID_LEN; i++) {
		fprintf(stderr, "%02x", (*c)&0xff);
		c++;
	}
	fprintf(stderr,"\n");
	fprintf(stderr,"  requestID: %d\n", req->requestID);
	fprintf(stderr,"  OID: ");
	c = req->OID_str;
	for (i = 0; i < req->OID_len; i++) {
		fprintf(stderr, "%02x", (*c)&0xff);
		c++;
	}
	fprintf(stderr,"\n");
	fprintf(stderr,"  OID_len: %d\n", req->OID_len);

}

uint32_t AuthenticatePDU(request *req, unsigned char *pkt, uint32_t msg_len, uint32_t AuthParamOffset) {
	unsigned char extendedAuthKey[64];
	unsigned char K1[64];
	unsigned char K2[64];
	unsigned char key[16];
	uint32_t i;
	MD5_CTX MD;

	if (req == NULL || pkt == NULL) {
		return(ERROR_NOACCESS);
	}

	// too easy
	if (req->AuthParamLen == 0) {
		return(ERROR_NOACCESS);
	}
		
	// replace pkt's MAC with \x00 * 12
	// bug should zero out 12 chars, not a user-supplied number
	bzero(pkt+AuthParamOffset, req->AuthParamLen);

	// derive K1 and K2 from secret authKey
	// extend the authKey to 64 octets by appending 48 zero octets
	bzero(extendedAuthKey, 64);
	password_to_key_md5(AUTH_PASSPHRASE, strlen(AUTH_PASSPHRASE), myAuthoritativeEngineID, myAuthoritativeEngineID_len, key);
	memcpy(extendedAuthKey, key, 16);
	// obtain K1 by XORing extendedAuthKey with IPAD (0x36*64)
	for (i = 0; i < 64; i++) {
		K1[i] = extendedAuthKey[i] ^ 0x36;
	}
	// obtain K2 by XORing extendedAuthKey with OPAD (0x5c*64)
	for (i = 0; i < 64; i++) {
		K2[i] = extendedAuthKey[i] ^ 0x5C;
	}

	// calculate MAC over wholeMsg
	// prepend K1 to wholeMsg and calculate MD5	
	MD5_Init(&MD);
	MD5_Update(&MD, K1, 64);
	for (i = 0; i < msg_len; ) {
		if (msg_len-i > 64) {
			MD5_Update(&MD, pkt+i, 64);
		} else {
			MD5_Update(&MD, pkt+i, msg_len-i);
		}
		i+=64;
	}	
	MD5_Final(key, &MD);
	// prepend K1 to the previous step's digest and calculate the MD5 over that
	MD5_Init(&MD);
	MD5_Update(&MD, K2, 64);
	MD5_Update(&MD, key, 16);
	// first 12 bytes of this key is the MAC
	MD5_Final(key, &MD);
	
	// see if the calculate MAC matches the packet's MAC
	// BUG, should be checking 12 chars, not user-defined length
	if (!memcmp(req->AuthParam, key, req->AuthParamLen)) {
		return(ERROR_NOERROR);
	} else {
		return(ERROR_NOACCESS);
	}

}

uint32_t DecryptPDU(request *req) {
	unsigned char key[16];
	unsigned char DES_key[8];
	unsigned char preIV[8];
	unsigned char IV[8];
	DES_key_schedule schedule;
	uint32_t i;
	unsigned char *c;

	// make sure privParameters is 8 bytes long
	if (req->PrivParamLen != 8) {
		return(ERROR_NOACCESS);
	}

	// make sure the encryptedPDU is a multiple of 8 bytes
	if (req->PDU_len % 8 != 0) {
		return(ERROR_NOACCESS);
	}

	// calculate the private key
	password_to_key_md5(PRIV_PASSPHRASE, strlen(PRIV_PASSPHRASE), myAuthoritativeEngineID, myAuthoritativeEngineID_len, key);

	// grab the DES key and preIV
	memcpy(DES_key, key, 8);
	memcpy(preIV, key+8, 8);

	// create the IV from the preIV and salt (req->PrivParam)
	for (i = 0; i < 8; i++) {
		IV[i] = req->PrivParam[i] ^ preIV[i];
	}

	// verify PDU_len is ok
	if (req->PDU_len > MAX_PKT_LEN) {
		return(ERROR_NOACCESS);
	}

	// decrypt the PDU
	DES_set_key((DES_cblock *)DES_key, &schedule);
	DES_ncbc_encrypt(req->encryptedPDU, req->plaintextPDU, req->PDU_len, &schedule, (DES_cblock *)IV, DES_DECRYPT);

	return(ERROR_NOERROR);
}

uint8_t ParseTLV(unsigned char *tlv, uint32_t target_type, int32_t target_len, int32_t *actual_len, void **value) {
	uint8_t *type;
	uint8_t *len;
	uint8_t len_bytes;

	if (tlv == NULL || actual_len == NULL || value == NULL)
		return(ERROR_GENERR);

	// get pointers to the type and len
	type = (uint8_t *)tlv;
	len = (uint8_t *)(tlv+1);

	// see if we have a multi-byte length
	if (*len > 0x7f) {
		len_bytes = *len & 0x7f;
		if (len_bytes > 1) {
			// don't allow TLV's larger than 255
			return(ERROR_TOOBIG);
		}
		len = (uint8_t *)(tlv+2);
		*value = tlv+3;
	} else {
		*value = tlv+2;
	}

	*actual_len = *len;

	// check the target values
	if (*type != target_type) {
		return(ERROR_BADVALUE);
	}
	if (target_len == VARIABLE_LEN) {
		if (*type == TYPE_NULL && *len != 0) {
			return(ERROR_TOOBIG);
		}
		if (*type == INTEGER) {
			if (!(*len == 1 || *len == 2 || *len == 4)) {
				return(ERROR_BADVALUE);
			}
		}
	} else {
		if (*len != target_len) {
			return(ERROR_TOOBIG);
		}
	}

	// successful parse
	return(ERROR_NOERROR);

}

uint8_t ParseInteger(void *value, uint32_t len, uint32_t *actual_value) {

	if (value == NULL || actual_value == NULL)
		return(ERROR_GENERR);

	if (len == 1) {
		*actual_value = *((uint8_t *)value);
	} else if (len == 2) {
		*actual_value = ntohs(*((uint16_t *)value));
	} else if (len == 4) {
		*actual_value = ntohl(*((uint32_t *)value));
	} else {
		return(ERROR_TOOBIG);
	}
	
	return(ERROR_NOERROR);
}

int ParsePDU(unsigned char *pkt, uint32_t curr_len, uint32_t msg_len, request *req) {
	int32_t len;
	void *value;
	uint32_t val32;
	uint8_t errval;

	if (pkt == NULL || req == NULL)
		return(ERROR_GENERR);

	// validate the sequence header
	if ((errval = ParseTLV(pkt+curr_len, SEQUENCE, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	// reset msg_len to the SEQUENCE's length since anything
	// more is DES padding
	msg_len = curr_len+TL_LEN+len;
	curr_len += TL_LEN;

	// contextEngineID
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, OCTET_STRING, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len || len > MAX_CONTEXT_ENGINE_ID_LEN) {
		return(ERROR_TOOBIG);
	}
	memcpy(req->contextEngineID, value, len);
	curr_len += TL_LEN+len;
	
	// contextName
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, OCTET_STRING, 0, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	curr_len += TL_LEN;
	
	// parse the PDU type (GetRequest)
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, GET_REQUEST, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	// get request length should be exactly the remaining pkt size
	if (curr_len+TL_LEN+len != msg_len) {
		return(ERROR_TOOBIG);
	}
	curr_len += TL_LEN;

	// parse the requestID
	if (curr_len+TL_LEN+4 > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, INTEGER, 4, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	req->requestID = val32;
	curr_len += TL_LEN+len;

	// parse the error-status
	if (curr_len+TL_LEN+1 > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, INTEGER, 1, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	if (val32 != 0) {
		return(ERROR_BADVALUE);
	}
	curr_len += TL_LEN+len;

	// parse the error-index
	if (curr_len+TL_LEN+1 > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, INTEGER, 1, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	if (val32 != 0) {
		return(ERROR_BADVALUE);
	}
	curr_len += TL_LEN+len;

	// parse the varbind sequence
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, SEQUENCE, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	// varbind sequence length should be exactly the remaining pkt size
	if (curr_len+TL_LEN+len != msg_len) {
		return(ERROR_TOOBIG);
	}
	// if the varbind sequence is zero, that means there are no OID's being requested
	// that's ok in the case of a DISCOVERY packet and for that type request
	// we are done parsing
	if (len == 0) {
		return(ERROR_NOERROR);
	}
	curr_len += TL_LEN;

	// parse the varbind
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, SEQUENCE, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	// varbind sequence length should be exactly the remaining pkt size
	if (curr_len+TL_LEN+len != msg_len) {
		return(ERROR_TOOBIG);
	}
	curr_len += TL_LEN;

	// parse the oid
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, OID, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (len > MAX_OID_LEN || curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	memcpy(req->OID_str, value, len);
	req->OID_len = len;
	curr_len += TL_LEN+len;

	// parse the value
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, TYPE_NULL, 0, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}

	return(ERROR_NOERROR);
}

int ParsePacket(unsigned char *pkt, request *req) {
	uint32_t msg_len;
	uint32_t curr_len = 0;
	uint32_t len;
	void *value;
	uint32_t val32;
	uint32_t AuthParamOffset;
	uint8_t errval;

	// validate the SNMPv3Message header
	if ((errval = ParseTLV(pkt+curr_len, SEQUENCE, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (len > 0x7f) {
		curr_len += 3;
	} else {
		curr_len += 2;
	}	
	msg_len = curr_len+len;

	// validate the snmp version
	if (curr_len+TL_LEN+1 > msg_len) {
		return(ERROR_GENERR);
	}
	if ((errval = ParseTLV(pkt+curr_len, INTEGER, 1, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	if (val32 != SNMP_VERSION_3) {
		return(ERROR_GENERR);
	}
	curr_len += TL_LEN + len;

	// validate the HeaderData
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_GENERR);
	}
	if ((errval = ParseTLV(pkt+curr_len, SEQUENCE, (TL_LEN+4+TL_LEN+4+TL_LEN+1+TL_LEN+1), &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	curr_len += TL_LEN;

	// validate the msgID TLV
	if (curr_len+TL_LEN+4 > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, INTEGER, 4, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	req->msgID = val32;
	curr_len += TL_LEN+len;


	// validate the msgMaxSize TLV
	if (curr_len+TL_LEN+4 > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, INTEGER, 4, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	curr_len += TL_LEN+len;

	// validate the msgFlags TLV
	if (curr_len+TL_LEN+1 > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, OCTET_STRING, 1, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	if (val32 & FLAG_REPORTABLE) {
		req->reportable = true;
	}
	if (val32 & FLAG_ENCRYPTED) {
		req->encrypted = true;
	}
	if (val32 & FLAG_AUTHENTICATED) {
		req->authenticated = true;
	}
	// error out if other bits are set in this field
	if (val32 & (0xFFFFFFFF ^ (FLAG_REPORTABLE|FLAG_ENCRYPTED|FLAG_AUTHENTICATED))) {
		return(ERROR_BADVALUE);
	}
	curr_len += TL_LEN+len;

	// validate the msgSecurityModel TLV
	if (curr_len+TL_LEN+1 > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, INTEGER, 1, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	if (val32 != USM) {
		return(ERROR_BADVALUE);
	}
	curr_len += TL_LEN+len;
	
	// validate the msgSecurityParameters
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, OCTET_STRING, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	curr_len += TL_LEN;

	// msgSecurityParameters SEQUENCE
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, SEQUENCE, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	curr_len += TL_LEN;

	// msgAuthoritativeEngineID	
	if (curr_len+TL_LEN > msg_len) {
		return(-1);
	}
	if ((errval = ParseTLV(pkt+curr_len, OCTET_STRING, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (len > 12) {
		return(ERROR_TOOBIG);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	// save a copy of this 
//	memcpy(&(req->EngineID)+(12-len), value, len);
	curr_len += TL_LEN+len;
		
	// msgAuthoritativeEngineBoots	
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, INTEGER, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	curr_len += TL_LEN+len;

	// msgAuthoritativeEngineTime
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, INTEGER, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	if (ParseInteger(value, len, &val32) != ERROR_NOERROR) {
		return(errval);
	}
	curr_len += TL_LEN+len;

	// msgUserName
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, OCTET_STRING, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	if (len > MAX_USERNAME_LEN-1) {
		return(ERROR_TOOBIG);
	}
	memcpy(&req->UserName, value, len);
	curr_len += TL_LEN+len;

	// msgAuthenticationParameters
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, OCTET_STRING, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	// technically the auth parameters should be 0 or 12, but we allow values between so the auth bug can be exploited
	if (len > MAX_AUTH_PARAM_LEN) {
		return(ERROR_TOOBIG);
	}
	memcpy(&req->AuthParam, value, len);
	req->AuthParamLen = len;
	// save a copy of the pkt offset to the value for easier Auth processing later
	AuthParamOffset = curr_len+TL_LEN;
	curr_len += TL_LEN+len;

	// msgPrivacyParameters
	if (curr_len+TL_LEN > msg_len) {
		return(ERROR_TOOBIG);
	}
	if ((errval = ParseTLV(pkt+curr_len, OCTET_STRING, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
		return(errval);
	}
	if (curr_len+TL_LEN+len > msg_len) {
		return(ERROR_TOOBIG);
	}
	if (len != 0 && len != MAX_PRIV_PARAM_LEN) {
		return(ERROR_TOOBIG);
	}
	memcpy(&req->PrivParam, value, len);
	req->PrivParamLen = len;
	curr_len += TL_LEN+len;

	// handle encrypted PDU
	if (req->encrypted) {
		// first authenticate it...no point in wasting time if that fails
		if (AuthenticatePDU(req, pkt, msg_len, AuthParamOffset) != ERROR_NOERROR) {
			return(ERROR_NOACCESS);
		}

		// check the username
		if (strlen(req->UserName) != strlen(USER)) {
			return(ERROR_NOACCESS);
		}
		if (strcmp(req->UserName, USER)) {
			return(ERROR_NOACCESS);
		}

		// extract the scopedPDU (the encrypted part of the packet)
		if (curr_len+TL_LEN > msg_len) {
			return(ERROR_TOOBIG);
		}
		if ((errval = ParseTLV(pkt+curr_len, OCTET_STRING, VARIABLE_LEN, &len, &value)) != ERROR_NOERROR) {
			return(errval);
		}
		if (curr_len+TL_LEN+len != msg_len) {
			return(ERROR_TOOBIG);
		}
		memcpy(req->encryptedPDU, value, len);
		req->PDU_len = len;
		curr_len += TL_LEN;

		// decrypt the scoped PDU
		if ((errval = DecryptPDU(req)) != ERROR_NOERROR) {
			return(errval);
		}

		// parse the decrypted PDU
		if ((errval = ParsePDU(req->plaintextPDU, 0, len, req)) != ERROR_NOERROR) {
			return(errval);
		}

	} else if (req->reportable) {

		if ((errval = ParsePDU(pkt, curr_len, msg_len, req)) != ERROR_NOERROR) {
			return(errval);
		}

		// since this should be a DISCOVERY request, make sure no varbind's were parsed
		if (req->OID_str[0] != '\0') {
			return(ERROR_BADVALUE);
		}
	}	

	return(ERROR_NOERROR);
	
}

uint8_t SendReport(request *req) {
	unsigned char pkt[1500];
	uint32_t curr_len = 0;
	uint32_t msg_len;
	uint32_t vb_seq_len;
	uint32_t report_len;
	uint32_t sec_len;
	uint32_t sec_seq_len;
	uint32_t val32;
	uint16_t val16;
	uint32_t total_sent_len;
	int32_t  sent_len;

	bzero(pkt, 1500);

	// create the SNMPv3Message tlv
	pkt[curr_len++] = SEQUENCE;
	msg_len = curr_len;
	pkt[curr_len++] = 0; // will set this later

	// create the version tlv
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = 3; 

	// create the HeaderData
	pkt[curr_len++] = SEQUENCE;
	pkt[curr_len++] = 16; 

	// create the msgID tlv
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 4;
	val32 = htonl(req->msgID);
	memcpy(pkt+curr_len, &val32, 4);
	curr_len += 4;

	// create the msgMaxSize TLV
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 2;
	val16 = htons(1500);
	memcpy(pkt+curr_len, &val16, 2);
	curr_len += 2;

	// create the msgFlags TLV
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = 0;

	// create the msgSecurityModel TLV
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = USM;

	// create the message security parameters envelope
	pkt[curr_len++] = OCTET_STRING;
	sec_len = curr_len;
	pkt[curr_len++] = 0;

	// create the message security parameters sequence
	pkt[curr_len++] = SEQUENCE;
	sec_seq_len = curr_len;
	pkt[curr_len++] = 0;

	// create the msgAuthoritativeEngineID TLV
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = myAuthoritativeEngineID_len;
	memcpy(pkt+curr_len, myAuthoritativeEngineID, myAuthoritativeEngineID_len);
	curr_len += myAuthoritativeEngineID_len;

	// create the msgAuthoritativeEngineBoots TLV
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = (uint8_t)msgAuthoritativeEngineBoots;

	// create the msAuthoritativeEngineTime TLV
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 4;
	val32 = htonl(myAuthoritativeEngineTime);
	memcpy(pkt+curr_len, &val32, 4);
	curr_len += 4;

	// create the msgUserName TLV
	pkt[curr_len++] = OCTET_STRING;
	if (req->UserName[0] != '\0') {
		pkt[curr_len++] = strlen(req->UserName);
		memcpy(pkt+curr_len, req->UserName, strlen(req->UserName));
		curr_len += strlen(req->UserName);
	} else {
		pkt[curr_len++] = 0;
	}

	// create the msgAuthenticationParameters
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = 0;

	// create the msgPrivacyParameters
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = 0;

	// set the message security parameter lengths
	pkt[sec_len] = curr_len - sec_len - 1;
	pkt[sec_seq_len] = curr_len - sec_seq_len - 1;

	// create the varbind sequence
	pkt[curr_len++] = SEQUENCE;
	vb_seq_len = curr_len;
	pkt[curr_len++] = 0; // will set this later

	// create the contextEngineID
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = myAuthoritativeEngineID_len;
	memcpy(pkt+curr_len, myAuthoritativeEngineID, myAuthoritativeEngineID_len);
	curr_len += myAuthoritativeEngineID_len;

	// create the contextName
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = 0;

	// create the report TLV
	pkt[curr_len++] = REPORT;
	report_len = curr_len;
	pkt[curr_len++] = 0; // will set this later

	// create the requestID
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 4; // will set this later
	val32 = htonl(req->requestID);
	memcpy(pkt+curr_len, &val32, 4);	
	curr_len += 4;

	// create the error-status
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1; 
	pkt[curr_len++] = req->ErrorStatus; 

	// create the error-index
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1; 
	pkt[curr_len++] = 0; 

	// create the varbind sequence
	pkt[curr_len++] = SEQUENCE;
	pkt[curr_len++] = 20; 

	// create the varbind
	pkt[curr_len++] = SEQUENCE;
	pkt[curr_len++] = 18; 

	// create the oid
	pkt[curr_len++] = OID;
	if (req->ErrorStatus == ERROR_NOACCESS) {
		pkt[curr_len++] = 10; 
		memcpy(pkt+curr_len, "\x2b\x06\x01\x06\x03\x0f\x01\x01\x05\x00", 10);
		curr_len += 10;
	} else {
		pkt[curr_len++] = 10; 
		memcpy(pkt+curr_len, "\x2b\x06\x01\x06\x03\x0f\x01\x01\x04\x00", 10);
		curr_len += 10;
	}

	// create the value
	pkt[curr_len++] = COUNTER32;
	pkt[curr_len++] = 4; 
	if (req->ErrorStatus == ERROR_NOACCESS) {
		val32 = htonl(FAIL_COUNT);
	} else {
		val32 = 0;
	}
	memcpy(pkt+curr_len, &val32, 4);
	curr_len += 4;

	// go back and set the lengths we needed to calculate	
	pkt[msg_len] = curr_len - msg_len - 1;
	pkt[vb_seq_len] = curr_len - vb_seq_len - 1; 
	pkt[report_len] = curr_len - report_len - 1; 

	total_sent_len = 0;
	while (total_sent_len < curr_len) {
		sent_len = write(0, pkt, curr_len-total_sent_len);
		if (sent_len <= 0) {
			return(ERROR_SILENTFAIL);
		}
		total_sent_len += sent_len;
	}
	fflush(stdout);

	return(0);
}

uint8_t HandleRequest(request *req) {
	int i, j;
	unsigned char *c;

	// see if the requested OID is in the MIB
	for (i = 0; i < MAX_MIBS; i++) {
		if (MIB[i].OID_len != req->OID_len) {
			continue;
		}
		if (!memcmp(MIB[i].OID_str, req->OID_str, MIB[i].OID_len)) {
			break;
		}
	}
	if (i == MAX_MIBS) {
		// nope
		return(ERROR_NOSUCHNAME);
	}

	// if so, populate the response data
	req->type = MIB[i].type;
	req->len = MIB[i].len;
	req->value = MIB[i].value;

	return(ERROR_NOERROR);
}

uint32_t EncryptPDU(unsigned char *pkt, uint32_t pdu_len, uint32_t curr_len, uint32_t msg_priv) {
	unsigned char key[16];
	unsigned char DES_key[8];
	unsigned char preIV[8];
	unsigned char IV[8];
	unsigned char salt[8];
	DES_key_schedule schedule;
	uint32_t i;
	uint32_t val32;
	unsigned char encryptedPDU[MAX_PKT_LEN];

	if ((curr_len - pdu_len + 1) % 8 != 0) {
		return(ERROR_GENERR);
	}
	if ((curr_len - pdu_len +1) > MAX_PKT_LEN) {
		return(ERROR_TOOBIG);
	}

	// calculate the private key
	password_to_key_md5(PRIV_PASSPHRASE, strlen(PRIV_PASSPHRASE), myAuthoritativeEngineID, myAuthoritativeEngineID_len, key);

	// grab the DES key and preIV
	memcpy(DES_key, key, 8);
	memcpy(preIV, key+8, 8);

	// create the salt
	val32 = htonl(msgAuthoritativeEngineBoots);
	memcpy(salt, &val32, 4);
	val32 = htonl(SaltInt++);
	memcpy(salt+4, &val32, 4);

	// encrypt the PDU
	DES_set_key((DES_cblock *)DES_key, &schedule);
	DES_ncbc_encrypt(pkt+pdu_len, encryptedPDU, curr_len-pdu_len+1, &schedule, (DES_cblock *)IV, DES_ENCRYPT);
	
	// copy the encrypted PDU back into the packet
	memcpy(pkt+pdu_len, encryptedPDU, curr_len - pdu_len + 1);

	// store the salt into the msgPrivacyParameters TLV
	memcpy(pkt+msg_priv, salt, 8);

	return(ERROR_NOERROR);
}

uint8_t CreateMsgAuth(unsigned char *pkt, uint32_t curr_len, uint32_t msg_auth) {
	unsigned char extendedAuthKey[64];
	unsigned char K1[64];
	unsigned char K2[64];
	unsigned char key[16];
	uint32_t i;
	MD5_CTX MD;
	unsigned char buf[16];
	unsigned int buf_len = 16;

	// derive K1 and K2 from secret authKey
	// extend the authKey to 64 octets by appending 48 zero octets
	bzero(extendedAuthKey, 64);
	password_to_key_md5(AUTH_PASSPHRASE, strlen(AUTH_PASSPHRASE), myAuthoritativeEngineID, myAuthoritativeEngineID_len, key);
	memcpy(extendedAuthKey, key, 16);

	// obtain K1 by XORing extendedAuthKey with IPAD (0x36*64)
	for (i = 0; i < 64; i++) {
		K1[i] = extendedAuthKey[i] ^ 0x36;
	}
	// obtain K2 by XORing extendedAuthKey with OPAD (0x5c*64)
	for (i = 0; i < 64; i++) {
		K2[i] = extendedAuthKey[i] ^ 0x5C;
	}

	HMAC(EVP_md5(), extendedAuthKey, 16, pkt, curr_len+1, buf, &buf_len); 

	// calculate MAC over wholeMsg
	// prepend K1 to wholeMsg and calculate MD5	
	MD5_Init(&MD);
	MD5_Update(&MD, K1, 64);
	for (i = 0; i <= curr_len; ) {
		if (curr_len-i > 64) {
			MD5_Update(&MD, pkt+i, 64);
		} else {
			MD5_Update(&MD, pkt+i, curr_len-i+1);
		}
		i+=64;
	}	
	MD5_Final(key, &MD);
	// prepend K2 to the previous step's digest and calculate the MD5 over that
	MD5_Init(&MD);
	MD5_Update(&MD, K2, 64);
	MD5_Update(&MD, key, 16);
	// first 12 bytes of this key is the MAC
	MD5_Final(key, &MD);
	
	// copy the MAC into the msgAuthenticationParameters TLV
	memcpy(pkt+msg_auth, key, 12);

	return(ERROR_NOERROR);
}

uint8_t SendResponse(request *req) {
	unsigned char pkt[MAX_PKT_LEN];
	uint32_t curr_len = 0;
	uint32_t msg_len;
	uint32_t msg_auth;
	uint32_t msg_priv;
	uint32_t vb_seq_len;
	uint32_t response_len;
	uint32_t sec_len;
	uint32_t sec_seq_len;
	uint32_t pdu_len;
	uint32_t pdu_len_offset;
	uint32_t val32;
	uint16_t val16;
	uint32_t total_sent_len;
	int32_t  sent_len;
	uint8_t errval;

	bzero(pkt, MAX_PKT_LEN);

	// create the SNMPv3Message tlv
	pkt[curr_len++] = SEQUENCE;
	msg_len = curr_len;
	pkt[curr_len++] = 0; // will set this later
	pkt[curr_len++] = 0; // will set this later

	// create the version tlv
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = 3; 

	// create the HeaderData
	pkt[curr_len++] = SEQUENCE;
	pkt[curr_len++] = 16; 

	// create the msgID tlv
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 4;
	val32 = htonl(req->msgID);
	memcpy(pkt+curr_len, &val32, 4);
	curr_len += 4;

	// create the msgMaxSize TLV
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 2;
	val16 = htons(MAX_PKT_LEN);
	memcpy(pkt+curr_len, &val16, 2);
	curr_len += 2;

	// create the msgFlags TLV
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = FLAG_REPORTABLE|FLAG_ENCRYPTED|FLAG_AUTHENTICATED;

	// create the msgSecurityModel TLV
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = USM;

	// create the message security parameters envelope
	pkt[curr_len++] = OCTET_STRING;
	sec_len = curr_len;
	pkt[curr_len++] = 0;

	// create the message security parameters sequence
	pkt[curr_len++] = SEQUENCE;
	sec_seq_len = curr_len;
	pkt[curr_len++] = 0;

	// create the msgAuthoritativeEngineID TLV
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = myAuthoritativeEngineID_len;
	memcpy(pkt+curr_len, myAuthoritativeEngineID, myAuthoritativeEngineID_len);
	curr_len += myAuthoritativeEngineID_len;

	// create the msgAuthoritativeEngineBoots TLV
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = (uint8_t)msgAuthoritativeEngineBoots;

	// create the msAuthoritativeEngineTime TLV
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 4;
	val32 = htonl(myAuthoritativeEngineTime);
	memcpy(pkt+curr_len, &val32, 4);
	curr_len += 4;

	// create the msgUserName TLV
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = strlen(req->UserName);
	memcpy(pkt+curr_len, req->UserName, strlen(req->UserName));
	curr_len += strlen(req->UserName);

	// create the msgAuthenticationParameters (zero'd for now)
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = 12;
	msg_auth = curr_len;
	bzero(pkt+curr_len, 12);
	curr_len += 12;

	// create the msgPrivacyParameters (left blank for now)
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = 8;
	msg_priv = curr_len;
	curr_len += 8;

	// set the message security parameter lengths
	pkt[sec_len] = curr_len - sec_len - 1;
	pkt[sec_seq_len] = curr_len - sec_seq_len - 1;

	// create the octet string header for the PDU
	pkt[curr_len++] = OCTET_STRING;
	pdu_len_offset = curr_len;
	pkt[curr_len++] = 0;
	
	// create the varbind sequence
	pdu_len = curr_len;
	pkt[curr_len++] = SEQUENCE;
	vb_seq_len = curr_len;
	pkt[curr_len++] = 0; // will set this later

	// create the contextEngineID
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = myAuthoritativeEngineID_len;
	memcpy(pkt+curr_len, myAuthoritativeEngineID, myAuthoritativeEngineID_len);
	curr_len += myAuthoritativeEngineID_len;

	// create the contextName
	pkt[curr_len++] = OCTET_STRING;
	pkt[curr_len++] = 0;

	// create the response TLV
	pkt[curr_len++] = GET_RESPONSE;
	response_len = curr_len;
	pkt[curr_len++] = 0; // will set this later

	// create the requestID
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 4; // will set this later
	val32 = htonl(req->requestID);
	memcpy(pkt+curr_len, &val32, 4);	
	curr_len += 4;

	// create the error-status
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1; 
	pkt[curr_len++] = 0; 

	// create the error-index
	pkt[curr_len++] = INTEGER;
	pkt[curr_len++] = 1; 
	pkt[curr_len++] = 0; 

	// create the varbind sequence
	pkt[curr_len++] = SEQUENCE;
	pkt[curr_len++] = 2 + 2 + req->OID_len + 2 + req->len; 

	// create the varbind
	pkt[curr_len++] = SEQUENCE;
	pkt[curr_len++] =  2 + req->OID_len + 2 + req->len; 

	// create the oid
	pkt[curr_len++] = OID;
	pkt[curr_len++] = req->OID_len; 
	memcpy(pkt+curr_len, req->OID_str, req->OID_len);
	curr_len += req->OID_len;

	// create the value
	pkt[curr_len++] = req->type;
	pkt[curr_len++] = req->len; 
	memcpy(pkt+curr_len, req->value, req->len);
	curr_len += req->len;

	// go back and set the lengths we needed to calculate before DES padding
	pkt[vb_seq_len] = curr_len - vb_seq_len - 1; 
	pkt[response_len] = curr_len - response_len - 1; 

	// round up to a multiple of 8 for DES
	while (((curr_len - pdu_len + 1) % 8) != 0) {
		pkt[curr_len++] = 0;
	}

	// set the lengths which are based on the padded PDU length
	pkt[msg_len] = 0x81;
	pkt[msg_len+1] = curr_len - msg_len - 1;
	pkt[pdu_len_offset] = curr_len - pdu_len_offset;

	// Encrypt the PDU
	if ((errval = EncryptPDU(pkt, pdu_len, curr_len, msg_priv)) != ERROR_NOERROR) {
		return(errval);
	}

	// Authenticate the message
	if ((errval = CreateMsgAuth(pkt, curr_len, msg_auth)) != ERROR_NOERROR) {
		return(errval);
	}

	total_sent_len = 0;
	while (total_sent_len < curr_len) {
		sent_len = write(0, pkt+total_sent_len, curr_len-total_sent_len+1);
		if (sent_len <= 0) {
			return(ERROR_SILENTFAIL);
		}
		total_sent_len += sent_len;
	}
	fflush(stdout);

	return(ERROR_NOERROR);
}

