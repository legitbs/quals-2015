#ifndef TREE_H
#define TREE_H

typedef struct _tree {
	uint8_t name;
	tlv data;
	struct _tree *child[256];
	tlv *auth;
} tree;

tree *InsertLeaf(unsigned char *, uint8_t, tlv *, tlv *, uint8_t);
void PrintLeaf(tree *, unsigned char *, uint8_t);
tree *FindOID(unsigned char *, uint8_t);
tree *FindNextOID(tree *, tree *, unsigned char *, uint8_t, unsigned char *, uint8_t *, req *);

#endif
