#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "proto.h"
#include "tree.h"

tree *MIB;

void InitTree(void) {

	if ((MIB = calloc(1, sizeof(tree))) == NULL) {
		exit(-1);
	}

}

tree *InsertLeaf(unsigned char *oid, uint8_t oid_len, tlv *data, tlv *auth, uint8_t clone) {
	tree *t;
	tree *new_leaf;
	int i;

	if (MIB == NULL || oid == NULL || data == NULL) {
		return(NULL);
	}

	t = MIB;

	// must begin with .1.3
	if (oid[0] != 0x2b) {
		return(NULL);
	}

	// find the tree leaf where this new tlv belongs
	for (i = 1; i < oid_len-1; i++) {
		if (t->child[oid[i]] == NULL) {
			break;
		}
		t = t->child[oid[i]];
	}

	// see if we found the last leaf
	if (i == oid_len-1) {
		// yep
		if (t->child[oid[i]] == NULL) {
			// insert the new leaf here
			if ((new_leaf = calloc(1, sizeof(tree))) == NULL) {
				return(NULL);
			}
			t->child[oid[i]] = new_leaf;

		} else {
			// replace the leaf data
			// free the previous leaf's value
			if (t->child[oid[i]]->data.value) {
				free(t->child[oid[i]]->data.value);
			}
			new_leaf = t->child[oid[i]];
		}

	} else {
		// didn't make it to the end, so create the preceeding branches
		for (; i < oid_len; i++) {
			if ((t->child[oid[i]] = calloc(1, sizeof(tree))) == NULL) {
				return(NULL);
			}
			t = t->child[oid[i]];
		}
		new_leaf = t;
	}

	// set up the authentication for this leaf
	new_leaf->auth = auth;

	// copy over the type and length
	memcpy(&(new_leaf->data), data, sizeof(tlv));

	// calloc memory for the value
	if (clone) {
		if ((new_leaf->data.value = calloc(1, new_leaf->data.len)) == NULL) {
			return(NULL);
		}
		memcpy(new_leaf->data.value, data->value, new_leaf->data.len);
	} else {
		new_leaf->data.value = data->value;
	}

	return(new_leaf);

}

void DestroyTree(tree *t) {
	int i;

	if (t == NULL) {
		return;
	}

	// free the value in the current tlv
	if (t->data.value) {
		free(t->data.value);
		t->data.value = NULL;
	}

	for (i = 0; i < 256; i++) {
		if (t->child[i]) {
			DestroyTree(t->child[i]);
			free(t->child[i]);
			t->child[i] = NULL;
		}
	}

}

/*
void PrintType(tlv *t) {
	if (t->type == TYPE_INTEGER) {
		fprintf(stderr, "INTEGER");
	} else if (t->type == TYPE_OCTETSTRING) {
		fprintf(stderr, "OCTET STRING");
	} else if (t->type == TYPE_NULL) {
		fprintf(stderr, "NULL");
	} else if (t->type == TYPE_OID) {
		fprintf(stderr, "OID");
	} else {	
		fprintf(stderr, "UNK");
	}

}
		
void PrintValue(tlv *t) {
	uint32_t v;
	char *s;
	int i;
	uint16_t curr_oid;

	if (t->type == TYPE_INTEGER) {
		if (t->len == 1) {
			v = *((uint8_t *)(t->value));
		} else if (t->len == 2) {
			v = *((uint16_t *)(t->value));
		} else if (t->len == 4) {
			v = *((uint32_t *)(t->value));
		}
		fprintf(stderr,"%u", v);
	} else if (t->type == TYPE_OCTETSTRING) {
		if ((s = calloc(1, (t->len)+1)) == NULL) {
			exit(-1);
		}
		memcpy(s, t->value, t->len);
		fprintf(stderr, "%s", s);
		free(s);
	} else if (t->type == TYPE_NULL) {
		fprintf(stderr, "NULL");
	} else if (t->type == TYPE_OID) {
		curr_oid = 0;
		for (i = 0; i < t->len; i++) {
			if (((unsigned char *)(t->value))[i] >= 0x80) {
				if (curr_oid) {
					fprintf(stderr, ">2 byte large OID value...\n");
					return;
				}
				curr_oid = (((unsigned char *)(t->value))[i] & 0x7F) * 128;
				continue;
			}
			curr_oid += ((unsigned char *)(t->value))[i];
			if (i == 0 && ((unsigned char *)(t->value))[0] == 0x2b) {
				fprintf(stderr, ".1.3.");
			} else if (i == (t->len)-1) {
				fprintf(stderr, "%d", curr_oid);
			} else {
				fprintf(stderr, "%d.", curr_oid);
			}
			curr_oid = 0;
		}	
	} else {
		fprintf(stderr, "Unk type");
	}

}

void PrintTree(void) {
	unsigned char oid[256];

	bzero(oid, 256);
	oid[0] = 1;
	oid[1] = 3;
	
	PrintLeaf(MIB, oid, 2);

}

void PrintLeaf(tree *t, unsigned char *oid, uint8_t depth) {
	int i;
	uint16_t curr_oid = 0;

	if (t == NULL) {
		return;
	}

	// print the current leaf's data
	if (t->data.type != 0) {
		fprintf(stderr, ".");
		for (i = 0; i < depth; i++) {
			if (oid[i] >= 0x80) {
				// this is a 2-byte OID value, add the lower 7 bits to the next oid value
				if (curr_oid) {
					fprintf(stderr, ">2 byte large OID value...\n");
					return;
				}
				curr_oid = (oid[i] & 0x7F) * 128;
				continue;
			} 
			curr_oid += oid[i];
			if (i == depth-1) {
				fprintf(stderr,"%d", curr_oid);
			} else {
				fprintf(stderr,"%d.", curr_oid);
			}
			curr_oid = 0;
		}
		fprintf(stderr, " ");
		PrintType(&(t->data));
		fprintf(stderr, " ");
		PrintValue(&(t->data));
		fprintf(stderr,"\n");
	}

	// traverse the child leaf
	for (i = 0; i < 256; i++) {
		if (t->child[i]) {
			oid[depth] = i;
			PrintLeaf(t->child[i], oid, depth+1);
		}
	}

}
*/

tree *FindOID(unsigned char *oid, uint8_t len) {
	tree *t;
	uint8_t i = 1;

	if (oid == NULL || MIB == NULL) {
		return(NULL);
	}

	if (oid[0] != 0x2b) {
		return(NULL);
	}

	t = MIB;

	while (t && i < len) {
		t = t->child[oid[i++]];
	}

	if (i != len) {
		return(NULL);
	} 

	return(t);

}

tree *FindNextOID(tree *start, tree *curr, unsigned char *oid, uint8_t len, unsigned char *nextoid, uint8_t *nextlen, req *r) {
	tree *t;
	tree *t1;
	tree *next;
	int i;

	if (oid == NULL || MIB == NULL) {
		return(NULL);
	}

	if (start == NULL) {
		if ((start = FindOID(oid, len)) == NULL) {
			return(NULL);
		}
		t = MIB;
		*nextlen = 1;
		nextoid[(*nextlen)-1] = oid[0];
		oid++;
		len--;
	} else {
		t = curr;
	}

	if (t == NULL) {
		return(NULL);
	}

	if (len == 0) {
		// we're at the top of the requested sub-tree, walk 
		// everything below
		for (i = 0; i < 256; i++) {
			if (t->child[i]) {
				(*nextlen)++;
				nextoid[(*nextlen)-1] = i;
				t1 = FindNextOID(start,t->child[i], oid, len, nextoid, nextlen, r);
				if (t1 != NULL) {
					return(t1);
				}
				(*nextlen)--;
			}
		}
		// no children found, see if it's where we started
		if (t == start) {
			return(NULL);
		} 
		// nope, so see if this is a valid leaf node
		if (t->data.type != 0) {

			// it's a valid leaf, see if the requestor is authorized for access to it
			if (t->auth) {
				if (r->community_len != t->auth->len || memcmp(r->community, t->auth->value, t->auth->len) != 0) {
					// invalid community, access denied
					return(NULL);
				}
			}

			// yep
			return(t);
		}
	} else {
		(*nextlen)++;
		nextoid[(*nextlen)-1] = oid[0];
		if ((next = (FindNextOID(start, t->child[oid[0]], oid+1, len-1, nextoid, nextlen, r))) == NULL) {
			(*nextlen)--;
			for (i = oid[0]+1; i < 256; i++) {
				if (t->child[i]) {
					(*nextlen)++;
					nextoid[(*nextlen)-1] = i;
					t1 = FindNextOID(start,t->child[i], oid+1, 0, nextoid, nextlen, r);
					if (t1 == NULL) {
						(*nextlen)--;
					}
					return(t1);
				}
			}
			// no children found, recurse back up
			return(NULL);
		} else {
			return(next);
		}
	}

	return(NULL);

}
