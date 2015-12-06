all: snmpv3

snmpv3: snmpv3.o proto.o proto.o
	gcc -g -pie -fPIE -o twentyfiveseventy snmpv3.o proto.o -lssl -lcrypto

snmpv3.o: snmpv3.c proto.h
	gcc -g -pie -fPIE -c snmpv3.c

proto.o: proto.c proto.h
	gcc -g -pie -fPIE -c proto.c 
