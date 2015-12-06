#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "proto.h"
#include "tree.h"

// number of SETs that have been performed
uint8_t SetCount;

// number of errors (authentication, bad formatting, etc)
uint8_t ErrCount;

/* SNMPv1 packet format
The following represents the heirarchy in a SNMPv1 packet.  
Intentions represent the fields which are encompassed by the parent
header's length field.  So for example, the Varbind Type length field
covers the total size of the OID TLV and Value TLV.

                        - Type                          Length         Expected Value
Message TL              - SEQUENCE                      variable
  Version TLV           - INTEGER                       1              0
  Community TLV         - OCTETSTRING                   1 < len < 8  
  PDU TL                - GET/SET/GETNEXT               variable
    Request ID TLV      - INTEGER                       1              1
    Error TLV           - INTEGER                       1              0
    Error Index TLV     - INTEGER                       1              0
    Varbind List TL     - SEQUENCE                      variable
      Varbind Type TL   - SEQUENCE                      variable
        OID TLV         - OID                           variable
        Value TLV       - INTEGER/OCTETSTRING/NULL/OID  variable
      Varbind Type TL 
        OID TLV
        Value TLV
      ...
*/
int ParseSnmpPkt(unsigned char *pkt, ssize_t pkt_len, req *r) {
	uint32_t curr_len;
	uint8_t count;
	uint8_t *type;
	uint8_t *len;
	void *value;
	uint32_t val;
	uint32_t varbind_end;

	if (pkt == NULL || r == NULL) {
		return(0);
	}

	// check the outer message wrapper
	type = (uint8_t *)pkt;
	len = type+1;
	// see if the MSB is set which means this byte is encoding a len > 127
	if (*len & 0x80) {
		// yep, we don't allow PDU's larger than 127 bytes, so bail
		return(0);
	}
	if (*type != TYPE_SEQUENCE || *len != pkt_len-TL_LEN) {
		return(0);
	}
	curr_len = TL_LEN;

	// make sure we have a proper SNMP version TLV 
	if (pkt_len < 5) {
		return(0);
	}
	type = (uint8_t *)(pkt+curr_len);
	len = type+1;
	value = len+1;
	if (*type != TYPE_INTEGER || *len != 1 || *(uint8_t *)value != 0) {
		return(0);
	}
	curr_len += TL_LEN+*len;
	r->version = *(uint8_t *)value;

	// check the comm string
	if (curr_len+TL_LEN > pkt_len) {
		return(0);
	}
	type = (uint8_t *)pkt+curr_len;
	len = type+1;
	value = len+1;
	if (*type != TYPE_OCTETSTRING || *len < 1 || *len > PRIV_COMM_LEN) {
		return(0);
	}
	if (curr_len+TL_LEN+*len > pkt_len) {
		return(0);
	}
	r->community = value;
	r->community_len = *len;
	curr_len += TL_LEN+*len;

	// check the PDU wrapper
	if (curr_len+TL_LEN > pkt_len) {
		return(0);
	}
	type = (uint8_t *)pkt+curr_len;
	len = type+1;
	value = len+1;
	if (*type == GET_REQUEST || *type == SET_REQUEST || *type == GET_NEXT_REQUEST) {
		r->type = *type;
	} else {
		return(0);
	}
	if (*len != pkt_len-curr_len-TL_LEN) {
		return(0);
	}
	curr_len += TL_LEN;

	// check the request ID
	if (curr_len+TL_LEN > pkt_len) {
		return(0);
	}
	type = (uint8_t *)pkt+curr_len;
	len = type+1;
	value = len+1;
	if (*type != TYPE_INTEGER || *len != 4) {
		return(0);
	}
	if (curr_len+TL_LEN+*len > pkt_len) {
		return(0);
	}
	// fix endienness
	memcpy(&val, value, 4);
	r->request_id = ntohl(val);
	curr_len += TL_LEN+*len;
	
	// check the error tlv
	if (curr_len+TL_LEN > pkt_len) {
		return(0);
	}
	type = (uint8_t *)pkt+curr_len;
	len = type+1;
	value = len+1;
	if (*type != TYPE_INTEGER || *len != 1 || *(uint8_t *)value != 0) {
		return(0);
	}
	curr_len += TL_LEN+*len;
	
	// check the error index
	if (curr_len+TL_LEN > pkt_len) {
		return(0);
	}
	type = (uint8_t *)pkt+curr_len;
	len = type+1;
	value = len+1;
	if (*type != TYPE_INTEGER || *len != 1 || *(uint8_t *)value != 0) {
		return(0);
	}
	curr_len += TL_LEN+*len;

	// decode the varbind list
	if (curr_len+TL_LEN > pkt_len) {
		return(0);
	}
	type = (uint8_t *)pkt+curr_len;
	len = type+1;
	value = len+1;
	if (*type != TYPE_SEQUENCE) {
		return(0);
	}
	if (curr_len+TL_LEN+*len != pkt_len) {
		return(0);
	}
	curr_len += TL_LEN;
	
	count = 0;
	while (curr_len < pkt_len) {
		// decode the first varbind
		if (curr_len+TL_LEN > pkt_len) {
			return(0);
		}
		type = (uint8_t *)pkt+curr_len;
		len = type+1;
		value = len+1;
		if (*type != TYPE_SEQUENCE) {
			return(0);
		}
		if (curr_len+TL_LEN+*len > pkt_len) {
			return(0);
		}
		varbind_end = curr_len+TL_LEN+*len;
		curr_len += TL_LEN;

		// decode the varbind's OID
		if (curr_len+TL_LEN > pkt_len) {
			return(0);
		}
		type = (uint8_t *)pkt+curr_len;
		len = type+1;
		value = len+1;
		if (*type != TYPE_OID) {
			return(0);
		}

		if (curr_len+TL_LEN+*len > pkt_len || curr_len+TL_LEN+*len > varbind_end) {
			return(0);
		}
		r->oid[count].type = *type;
		r->oid[count].len = *len;
		r->oid[count].value = value;
		curr_len += TL_LEN+*len;

		// decode the varbind value
		if (curr_len+TL_LEN > pkt_len) {
			return(0);
		}
		type = (uint8_t *)pkt+curr_len;
		len = type+1;
		value = len+1;
		if (curr_len+TL_LEN+*len > pkt_len || curr_len+TL_LEN+*len > varbind_end) {
			return(0);
		}
		r->value[count].type = *type;
		r->value[count].len = *len;
		if (*type == TYPE_NULL) {
			r->value[count].value = NULL;
		} else if (*type == TYPE_INTEGER) {
			if (*len == 4 || *len == 2 || *len == 1) {
				r->value[count].value = value;
			} else {
				return(0);
			}
		} else if (*type == TYPE_OID) {
			if (*len > 50) {
				return(0);
			}
			r->value[count].value = value;
		} else if (*type == TYPE_OCTETSTRING) {
			if (*len > 127) {
				return(0);
			}
			r->value[count].value = value;
		} else {
			// unknown type
			return(0);
		}
			
		curr_len += TL_LEN+*len;

		if (curr_len != varbind_end) {
			return(0);
		}

		count++;
	}
	r->count = count;

}

/*
void PrintRequest(req *r) {
	int i;
	int l;
	unsigned char *value;

	fprintf(stderr,"version: %d\n", r->version);
	fprintf(stderr,"community: %s\n", r->community);
	fprintf(stderr,"type: %02x\n", r->type);
	fprintf(stderr,"request_id: %u\n", r->request_id);
	for (i = 0; i < r->count; i++) {

		fprintf(stderr,"varbind: %d\n", i);
		fprintf(stderr,"  type: %02x\n", r->oid[i].type);
		fprintf(stderr,"  length: %d\n", r->oid[i].len);
		fprintf(stderr,"  value: ");
		value = (unsigned char *)r->oid[i].value;
		for (l = 0; l < r->oid[i].len; l++) {
			fprintf(stderr,"%02x:", value[l]);
		}
		fprintf(stderr,"\n");
	}

}
*/

#define MAX_MSG_SIZE (127)
void SendResponse(req *r) {
	unsigned char pkt[1500];
	uint32_t curr_len = 0;
	uint32_t msg_len_offset, pdu_len_offset, vb_seq_len_offset;
	uint8_t i;
	uint32_t len;
	uint32_t request_id;
	uint32_t val;
	uint32_t total_sent;

	bzero(pkt, MAX_MSG_SIZE+TL_LEN);

	// create the message tlv
	pkt[curr_len++] = TYPE_SEQUENCE;
	msg_len_offset = curr_len;
	pkt[curr_len++] = 0; // will set this later

	// create the version tlv
	pkt[curr_len++] = TYPE_INTEGER;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = 0; // SNMP version 1

	// create the community tlv
	pkt[curr_len++] = TYPE_OCTETSTRING;
	pkt[curr_len++] = r->community_len;
	memcpy(pkt+curr_len, r->community, r->community_len);
	curr_len += r->community_len;

	// create the pdu tlv
	pkt[curr_len++] = GET_RESPONSE;
	pdu_len_offset = curr_len;
	pkt[curr_len++] = 0; // will set this later

	// create the request_id tlv
	pkt[curr_len++] = TYPE_INTEGER;
	pkt[curr_len++] = 4;
	request_id = htonl(r->request_id);
	memcpy(&(pkt[curr_len]), &request_id, 4);
	curr_len += 4;

	// create the error tlv
	pkt[curr_len++] = TYPE_INTEGER;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = r->error;

	// create the error index tlv
	pkt[curr_len++] = TYPE_INTEGER;
	pkt[curr_len++] = 1;
	pkt[curr_len++] = r->error_index;

	// create the varbind list
	pkt[curr_len++] = TYPE_SEQUENCE;
	vb_seq_len_offset = curr_len;
	pkt[curr_len++] = 0;

	for (i = 0; i < r->count; i++) {
		if (curr_len+TL_LEN+(TL_LEN+r->oid[i].len)+(TL_LEN+r->value[i].len) > MAX_MSG_SIZE) {
			return;
		}

		// create the varbind tlv
		pkt[curr_len++] = TYPE_SEQUENCE;
		pkt[curr_len++] = (TL_LEN+r->oid[i].len)+(TL_LEN+r->value[i].len);

		// create the oid tlv
		pkt[curr_len++] = TYPE_OID;
		pkt[curr_len++] = r->oid[i].len;
		memcpy(pkt+curr_len, r->oid[i].value, r->oid[i].len);
		curr_len += r->oid[i].len;

		// create the value tlv
		pkt[curr_len++] = r->value[i].type;
		pkt[curr_len++] = r->value[i].len;
		if (r->value[i].type == TYPE_INTEGER) {
			if (r->value[i].len == 4) {
				val = htonl(*((uint32_t *)(r->value[i].value)));
			} else if (r->value[i].len == 2) {
				val = htons(*((uint16_t *)(r->value[i].value)));
			} else {
				val = *((uint8_t *)(r->value[i].value));
			}
			memcpy(pkt+curr_len, &val, r->value[i].len);
			curr_len += r->value[i].len;
		} else {
			memcpy(pkt+curr_len, r->value[i].value, r->value[i].len);
			curr_len += r->value[i].len;
		}
	}

	pkt[msg_len_offset] = curr_len-msg_len_offset-1;
	pkt[pdu_len_offset] = curr_len-pdu_len_offset-1;
	pkt[vb_seq_len_offset] = curr_len-vb_seq_len_offset-1;

	total_sent = 0;
	while (total_sent < curr_len) {
		if ((len = write(0, pkt, curr_len-total_sent)) >= 0) {
			total_sent += len;
		} else {
			fprintf(stderr, "Write failed with %d\n", len);
		}
	}
}

int32_t Authenticate(req *r, tlv **auth) {
	unsigned char oid[11];
	tree *t;
	uint8_t index = 1;

	// make sure the r->community is at least one we know about
	// get the OID of the snmp community strings
	memcpy(oid, "\x2b\x06\x01\x06\x03\x12\x01\x01\x01\x00\x02", 11);
	
	// check the first 10 community values
	for (index = 1; index < 11; index++) {
		oid[9] = index;
		if ((t = FindOID(oid, 11)) == NULL) {
			continue;
		}
		if (r->community_len == t->data.len) {
			if (memcmp(r->community, t->data.value, r->community_len) == 0) {
				*auth = &(t->data);
				if (memcmp(r->community, "public", 6) == 0) {
					return(AUTH_READ);
				} else {
					return(AUTH_WRITE);
				}
			}
		}
	}

	*auth = NULL;
	return(AUTH_DENIED);
}

void HandleGetRequest(req *r) {
	uint8_t i;
	tlv *oid;
	tree *t;
	req response;
	tlv *auth;
	
	if (r == NULL) {
		return;
	}

	// basic authentication to make sure the community provided is even valid
	if (Authenticate(r, &auth) == AUTH_DENIED) {
		ErrCount++;
		return;
	}

	bzero(&response, sizeof(req));
	response.version = r->version;
	response.community = r->community;
	response.community_len = r->community_len;
	response.type = GET_RESPONSE;
	response.request_id = r->request_id;
	response.count = r->count;

	// handle each oid
	for (i = 0; i < r->count; i++) {
		oid = &(r->oid[i]);
		memcpy(&(response.oid[i]), oid, sizeof(tlv));
		if ((t = FindOID((unsigned char *)oid->value, oid->len)) == NULL) {
			if (response.error == ERROR_NOERROR) {
				response.error = ERROR_NOTFOUND;
				response.error_index = i;
			}
			response.value[i].type = TYPE_NULL;
			response.value[i].len = 0;
			continue;
		}
		// found the OID, but check its type
		if (t->data.type == 0) {
			// invalid
			if (response.error == ERROR_NOERROR) {
				response.error = ERROR_NOTFOUND;
				response.error_index = i;
			}
			response.value[i].type = TYPE_NULL;
			response.value[i].len = 0;
			continue;
		} else {
			// see if the requesting client is authorized for this tlv
			if (t->auth) {
				if (r->community_len != t->auth->len || memcmp(r->community, t->auth->value, t->auth->len) != 0) {
					ErrCount++;
					// invalid community, access denied
					if (response.error == ERROR_NOERROR) {
						response.error = ERROR_NOTFOUND;
						response.error_index = i;
					}
					response.value[i].type = TYPE_NULL;
					response.value[i].len = 0;
					continue;
				}
			}
			
			response.value[i].type = t->data.type;
			// BUG allowing reads past object's length
			response.value[i].len = (t->data.len > r->value[i].len) ? t->data.len : r->value[i].len;
			response.value[i].value = t->data.value;
		}
	}	

	SendResponse(&response);

}

void HandleGetNextRequest(req *r) {
	uint8_t i;
	tlv *oid;
	tree *t;
	req response;
	unsigned char nextoid[256];
	uint8_t nextlen = 0;
	tlv *auth;
	
	if (r == NULL) {
		return;
	}

	// basic authentication to make sure the community provided is even valid
	if (Authenticate(r, &auth) == AUTH_DENIED) {
		ErrCount++;
		return;
	}

	bzero(&response, sizeof(req));
	response.version = r->version;
	response.community = r->community;
	response.community_len = r->community_len;
	response.type = GET_RESPONSE;
	response.request_id = r->request_id;
	response.count = r->count;

	// handle each oid
	for (i = 0; i < r->count; i++) {
		oid = &(r->oid[i]);
		if ((t = FindNextOID(NULL, NULL, (unsigned char *)oid->value, oid->len, nextoid, &nextlen, r)) == NULL) {
			if (response.error == ERROR_NOERROR) {
				response.error = ERROR_NOTFOUND;
				response.error_index = i;
			}
			response.value[i].type = TYPE_NULL;
			response.value[i].len = 0;
			continue;
		}
		memcpy(oid->value, nextoid, nextlen);
		oid->len = nextlen;
		memcpy(&(response.oid[i]), oid, sizeof(tlv));
		response.value[i].type = t->data.type;
		response.value[i].len = t->data.len;
		response.value[i].value = t->data.value;
	}	

	SendResponse(&response);

}

int CreateNewOID(req *response, uint8_t i, req *r, tlv *auth) {
	tlv *oid;
	tlv new_leaf;

	// get the OID
	oid = &(r->oid[i]);

	// populate a new leaf TLV
	new_leaf.type = r->value[i].type;
	new_leaf.len = r->value[i].len;
	new_leaf.value = r->value[i].value;

	// Insert the new leaf
	if (InsertLeaf(oid->value, oid->len, &new_leaf, auth, 1) == NULL) {
		fprintf(stderr, "Failed to insert leaf\n");
		exit(-1);
	}

	// form up the response
	response->value[i].type = new_leaf.type;
	response->value[i].len = new_leaf.len;
	response->value[i].value = new_leaf.value;

	return(0);

}

void HandleSetRequest(req *r) {
	uint8_t i;
	tlv *oid;
	tree *t;
	req response;
	uint32_t val;
	tlv *auth;
	
	if (r == NULL) {
		return;
	}

	// basic authentication to make sure the community provided is even valid
	if (Authenticate(r, &auth) != AUTH_WRITE) {
		ErrCount++;
		return;
	}

	bzero(&response, sizeof(req));
	response.version = r->version;
	response.community = r->community;
	response.community_len = r->community_len;
	response.type = GET_RESPONSE;
	response.request_id = r->request_id;
	response.count = r->count;

	// handle each oid
	for (i = 0; i < r->count; i++) {
		oid = &(r->oid[i]);
		memcpy(&(response.oid[i]), oid, sizeof(tlv));
		if ((t = FindOID((unsigned char *)oid->value, oid->len)) == NULL) {
			// only allow a few SETs per connection that create new objects
			if (SetCount < MAX_SET_PER_SESSION) {
				SetCount++;
				if (CreateNewOID(&response, i, r, auth) == 0) {
					continue;
				}
			}
			if (response.error == ERROR_NOERROR) {
				response.error = ERROR_NOTFOUND;
				response.error_index = i;
			}
			response.value[i].type = TYPE_NULL;
			response.value[i].len = 0;
			response.value[i].value = r->value[i].value;
			continue;
		}
		// see if the requesting client is authorized for this OID
		if (t->auth) {
			if (r->community_len != t->auth->len || memcmp(r->community, t->auth->value, t->auth->len) != 0) {
				ErrCount++;
				// invalid community, access denied
				if (response.error == ERROR_NOERROR) {
					response.error = ERROR_NOTFOUND;
					response.error_index = i;
				}
				response.value[i].type = TYPE_NULL;
				response.value[i].len = 0;
				continue;
			}
		}
		// found the OID, but check that its type matches the request
		if (t->data.type != r->value[i].type) {
			// invalid
			if (response.error == ERROR_NOERROR) {
				response.error = ERROR_BADTYPE;
				response.error_index = i;
			}
			response.value[i].type = r->value[i].type;
			response.value[i].len = r->value[i].len;
			response.value[i].value = r->value[i].value;
			continue;
		}

		// found the OID, but check that the value is within limits
		if (t->data.type == TYPE_INTEGER) {
			if (t->data.len != r->value[i].len) {
				// invalid
				if (response.error == ERROR_NOERROR) {
					response.error = ERROR_TOOLARGE;
					response.error_index = i;
				}
				response.value[i].type = r->value[i].type;
				response.value[i].len = r->value[i].len;
				response.value[i].value = r->value[i].value;
				continue;
			}
			// otherwise, update the object
			memcpy(t->data.value, r->value[i].value, r->value[i].len);
			// fix any endienness issues
			if (r->value[i].len == 4) {
				*((uint32_t *)t->data.value) = htonl(*((uint32_t *)(t->data.value)));
			} else if (r->value[i].len == 2) {
				*((uint16_t *)t->data.value) = htonl(*((uint16_t *)(t->data.value)));
			} 

		} else if (t->data.type == TYPE_OCTETSTRING || t->data.type == TYPE_OID || t->data.type == TYPE_SEQUENCE) {
			if (r->value[i].len > 256) {
				// invalid
				if (response.error == ERROR_NOERROR) {
					response.error = ERROR_TOOLARGE;
					response.error_index = i;
				}
				response.value[i].type = r->value[i].type;
				response.value[i].len = r->value[i].len;
				continue;
			}
			// otherwise, update the object
			// first free the current data

/*			Leaving this out is a BUG
			if (t->data.len != r->value[i].len) {
				if (t->data.value != NULL) {
					free(t->data.value);
				}
				if ((t->data.value = calloc(1, r->value[i].len)) == NULL) {
					exit(-1);
				}
				t->data.len = r->value[i].len;
			}
*/
			memcpy(t->data.value, r->value[i].value, r->value[i].len);
			
		} else if (t->data.type == TYPE_NULL) {
			if (oid->len > 0) {
				// invalid
				if (response.error == ERROR_NOERROR) {
					response.error = ERROR_TOOLARGE;
					response.error_index = i;
				}
				response.value[i].type = oid->type;
				response.value[i].len = oid->len;
				continue;
			}
			// nothing to do since null values are already null
		}

	
		response.value[i].type = t->data.type;
		response.value[i].len = t->data.len;
		response.value[i].value = t->data.value;
	}	

	SendResponse(&response);

}

