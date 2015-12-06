all: time-vortex wwtw

time-vortex: time-vortex.c common.h
	gcc -pie -fPIE -m32 -o time-vortex time-vortex.c

wwtw: wwtw.o angels.o
	gcc -pie -fPIE -m32 -o wwtw wwtw.o angels.o

wwtw.o: wwtw.c common.h
	gcc -pie -fPIE -m32 -Wno-format-security -c wwtw.c

angels.o: angels.c
	gcc -pie -fPIE -m32 -c angels.c
