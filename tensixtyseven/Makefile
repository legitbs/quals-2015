all: snmpv1

snmpv1: snmpv1.o tree.o proto.o
	mips-linux-gnu-gcc -EL -pie -fPIE -o tensixtyseven snmpv1.o tree.o proto.o

snmpv1.o: snmpv1.c tree.h proto.h
	mips-linux-gnu-gcc -EL -pie -fPIE -c snmpv1.c

proto.o: proto.c tree.h proto.h
	mips-linux-gnu-gcc -EL -pie -fPIE -c proto.c

tree.o: tree.c tree.h proto.h
	mips-linux-gnu-gcc -EL -pie -fPIE -c tree.c
