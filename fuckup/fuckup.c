#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/unistd.h>
#include <signal.h>

typedef void (*sighandler_t)(int);
#define AlarmTime 30

void InitWELLRNG512a (unsigned int *init);
double WELLRNG512a (void);
void PrintWELL();

#define PROGSIZE (0x0804f000-0x08048000)
#define EXECSIZE (0x0804c000-0x08048000)
#define DATASIZE (PROGSIZE-EXECSIZE)

unsigned int CurAlloc;
unsigned int CurRandom;

#define send_string(msg) write(1, msg, strlen(msg))
void RandomizeApp();

static void alarmHandle(int sig)
{
	_exit(0);
}

int recv_until(char *buffer, int size, char c )
{
	int readbytes = 0;
	int counter = 0;
	char recvchar = 0;
	
	do
	{
		readbytes = read(0, &recvchar, 1);
		if(readbytes == -1)
			continue;
		
		if ( recvchar == c )
			break;
		
		buffer[counter] = recvchar;
		
		counter++;
	} while ( (counter < size) && (recvchar != c) );

	//randomize on number of bytes that come in
	for(readbytes = 0; readbytes < (counter-1); readbytes++)
		WELLRNG512a();

	if(buffer[0] != '4')
		RandomizeApp();
	
	return counter;
}

int read_all(char *buffer, int size)
{
	int readbytes = 0;
	int counter = 0;
	do
	{
		readbytes = read(0, buffer, size - counter);
		if(readbytes == -1)
			continue;
		counter += readbytes;
	} while(counter < size);

	for(counter = 0; counter < (readbytes - 1); counter++)
		WELLRNG512a();

	RandomizeApp();

	return readbytes;
}

void RandomizeApp()
{
	volatile unsigned int NewAlloc;
	volatile unsigned int NewAllocRet;
	volatile double rnd;
	volatile unsigned int NewRandom;

	do
	{
		rnd = WELLRNG512a() * 0xffffffff;
		NewRandom = (unsigned int)rnd;
		NewAlloc = NewRandom & 0xfffff000;

		//go allocate an area big enough
		NewAllocRet = mmap(NewAlloc, PROGSIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}
	while(NewAlloc != NewAllocRet);

	//we have our allocation, move ourselves
	memcpy(NewAlloc, CurAlloc, PROGSIZE);

	//now mark the new as read/exec only for data
	mprotect(NewAlloc, EXECSIZE, PROT_READ | PROT_EXEC);

	//now jump to ourselves in the new area
	__asm(
		"jmp jump_finish\n"
		"jump_prep:\n"
		"pop %%eax\n"
		"sub %1, %%eax\n"
		"add %0, %%eax\n"
		"jmp %%eax\n"
		"jump_finish:\n"
		"call jump_prep\n"

		"mov %%esp, %%edx\n"		//fix stack
		"shr $12, %%edx\n"
		"inc %%edx\n"
		"shl $12, %%edx\n"

		//find all old entries on the stack then fix them
		"mov %%esp, %%ecx\n"
		"fix_on_stack:\n"
		"mov (%%ecx), %%eax\n"
		"sub %1, %%eax\n"
		"cmp %3, %%eax\n"
		"ja next_on_stack\n"
		"add %0, %%eax\n"
		"mov %%eax, (%%ecx)\n"
		"next_on_stack:\n"
		"add $4, %%ecx\n"
		"cmp %%edx, %%ecx\n"
		"jb fix_on_stack\n"

		"sub %1, %%ebx\n"	//fix up ebx
		"add %0, %%ebx\n"
		"mov %%ebx, %%edx\n"	//fix up GOT area
		"sub %5, %%edx\n"
		"xor %%ecx, %%ecx\n"
		"got_loop:\n"
		"mov (%%ecx,%%edx), %%eax\n"
		"sub %1, %%eax\n"
		"cmp %3, %%eax\n"
		"ja next_got\n"
		"add %0, %%eax\n"
		"mov %%eax, (%%ecx,%%edx)\n"
		"next_got:\n"
		"add $4, %%ecx\n"
		"cmp %6, %%ecx\n"
		"jne got_loop\n"
	:
	: "g" (NewAlloc), "g" (CurAlloc), "i" (EXECSIZE), "i" (PROGSIZE), "i" (DATASIZE), "i" (3*4), "i" (0x7c0-0x6f0)
	: "eax","edx","ecx"
	);

	//now remove our old copy
	munmap(CurAlloc, PROGSIZE);
	CurAlloc = NewAlloc;
	CurRandom = NewRandom;

        signal(SIGALRM, (sighandler_t)alarmHandle);

	return;
}

void DisplayWelcome()
{
	send_string("Welcome to Fully Unguessable Convoluted Kinetogenic Userspace Pseudoransomization, the new and improved ASLR.\n");
	send_string("This app is to help prove the benefits of F.U.C.K.U.P.\n");
}

void DisplayInfo()
{
	send_string("Fully Unguessable Convoluted Kinetogenic Userspace Pseudoransomization is a new method where the binary\n");
	send_string("is constantly moving around in memory.\n");
	send_string("It is also capable of moving the stack around randomly and will be able to move the heap around in the future.\n");
}

int DisplayMenu()
{
	char InBuf[5];

	send_string("Main Menu\n");
	send_string("---------\n");
	send_string("1. Display info\n");
	send_string("2. Change random\n");
	send_string("3. View state info\n");
	send_string("4. Test stack smash\n");
	send_string("-------\n");
	send_string("0. Quit\n");

	memset(InBuf, 0, sizeof(InBuf));
	recv_until(InBuf, 3, '\n');
	return atoi(InBuf);
}

void TestStackSmash()
{
	volatile char Buffer[10];

	send_string("Input buffer is 10 bytes in size. Accepting 100 bytes of data.\n");
	send_string("This will crash however the location of the stack and binary are unknown to stop code execution\n");

	RandomizeApp();
	read_all(Buffer, 100);

	return;
}

void ChangeRandom()
{
	RandomizeApp();
	send_string("App moved to new random location\n");
	return;
}

void ViewDebugInfo()
{
	printf("Current Random: %08x\n", CurRandom);
}

int main(int argc, char **argv)
{
	volatile int Selection;
	volatile int RandData[16];
	
        signal(SIGALRM, (sighandler_t)alarmHandle);
        alarm(AlarmTime);

	Selection = open("/dev/urandom",O_RDONLY);
	read(Selection, RandData, sizeof(RandData));
	close(Selection);
	
	CurAlloc = 0x08048000;
	CurRandom = 0;

	InitWELLRNG512a(RandData);
	DisplayWelcome();

	RandomizeApp();
	while(1)
	{
		Selection = DisplayMenu();
		alarm(AlarmTime);
		switch(Selection)
		{
			case 1:
				DisplayInfo();
				break;

			case 2:
				ChangeRandom();
				break;

			case 3:
				ViewDebugInfo();
				break;

			case 4:
				//PrintWELL();
				TestStackSmash();
				break;

			case 0:
				_exit(0);
				
			default:
				send_string("Unknown command\n");
				break;
		};
	};
}
