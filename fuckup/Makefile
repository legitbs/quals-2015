all:
	legitbs-gcc -nostdlib fuckup.c WELL512a.c -mplt -fPIC -fpic -o fuckup -Wall -m32 -Os -static -fno-stack-protector -D_FORTIFY_SOURCE=0 -lc -L/home/lightning/uClibc/usr/i386-linux-uclibc/usr/lib
	#legitbs-gcc test.c -o test -Wall -m32 -Os -fpic -fPIC -static -fno-stack-protector -D_FORTIFY_SOURCE=0
	strip -s fuckup 
	strip -g fuckup 
	strip -X fuckup 
	strip -x fuckup 

clean:
	rm *.o
	rm fuckup
