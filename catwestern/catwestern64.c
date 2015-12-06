#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

unsigned long long rax = 0;
unsigned long long rbx = 0;
unsigned long long rcx = 0;
unsigned long long rdx = 0;
unsigned long long rsi = 0;
unsigned long long rdi = 0;
unsigned long long r8 = 0;
unsigned long long r9 = 0;
unsigned long long r10 = 0;
unsigned long long r11 = 0;
unsigned long long r12 = 0;
unsigned long long r13 = 0;
unsigned long long r14 = 0;
unsigned long long r15 = 0;

int main( int argc, char **argv )
{
    int fd = 0;
    int length = 0;

    char *sc = NULL;

    if ( argc != 16 ) {
        printf("[ERROR] All regs and the code is necessary\n");
        exit(0);
    }

    rax = strtoll( argv[1], NULL, 16 );
    rbx = strtoll( argv[2], NULL, 16 );
    rcx = strtoll( argv[3], NULL, 16 );
    rdx = strtoll( argv[4], NULL, 16 );
    rsi = strtoll( argv[5], NULL, 16 );
    rdi = strtoll( argv[6], NULL, 16 );
    r8 = strtoll( argv[7], NULL, 16 );
    r9 = strtoll( argv[8], NULL, 16 );
    r10 = strtoll( argv[9], NULL, 16 );
    r11 = strtoll( argv[10], NULL, 16 );
    r12 = strtoll( argv[11], NULL, 16 );
    r13 = strtoll( argv[12], NULL, 16 );
    r14 = strtoll( argv[13], NULL, 16 );
    r15 = strtoll( argv[14], NULL, 16 );

    fd = open( argv[15], O_RDONLY );

    if ( fd <= 0 ) {
        printf("[ERROR] Failed to open %s\n", argv[15]);
        exit(0);
    }
 
    length = lseek( fd, 0, SEEK_END);
    lseek( fd, 0, SEEK_SET);

    sc = mmap( NULL, length, PROT_READ | PROT_WRITE|PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE, 0, 0 );

    if ( sc == NULL ) {
        printf("[ERROR] Failed to malloc %d bytes\n", length);
        close(fd);
        exit(0);
    }

    memset(sc, 0, length );
    read( fd, sc, length );

    close(fd);

    asm volatile (
                    "push %rax\n\t"
                    "push %rbx\n\t"
                    "push %rcx\n\t"
                    "push %rdx\n\t"
                    "push %rsi\n\t"
                    "push %rdi\n\t"
                    "push %r8\n\t"
                    "push %r9\n\t"
                    "push %r10\n\t"
                    "push %r11\n\t"
                    "push %r12\n\t"
                    "push %r13\n\t"
                    "push %r14\n\t"
                    "push %r15\n\t" );

    asm volatile (
                    "mov rax, %%rax\n\t"
                    "mov rbx, %%rbx\n\t"
                    "mov rcx, %%rcx\n\t"
                    "mov rdx, %%rdx\n\t"
                    "mov rsi, %%rsi\n\t"
                    "mov rdi, %%rdi\n\t"
                    "mov r8, %%r8\n\t"
                    "mov r9, %%r9\n\t"
                    "mov r10, %%r10\n\t"
                    "mov r11, %%r11\n\t"
                    "mov r12, %%r12\n\t"
                    "mov r13, %%r13\n\t"
                    "mov r14, %%r14\n\t"
                    "mov r15, %%r15\n\t"
        : : "m" (rax), "m" (rbx), "m" (rcx), "m" (rdx), "m" (rsi), "m" (rdi), "m" (r8), "m" (r9), "m" (r10), "m" (r11), "m" (r12), "m" (r13), "m" (r14), "m" (r15)
        );

    asm volatile (
                    "call *%0\n\t"
                    : : "m" (sc) : );

    asm volatile ( 
                    "mov %%rax, rax\n\t"
                    "mov %%rbx, rbx\n\t"
                    "mov %%rcx, rcx\n\t"
                    "mov %%rdx, rdx\n\t"
                    "mov %%rsi, rsi\n\t"
                    "mov %%rdi, rdi\n\t"
                    "mov %%r8, r8\n\t"
                    "mov %%r9, r9\n\t"
                    "mov %%r10, r10\n\t"
                    "mov %%r11, r11\n\t"
                    "mov %%r12, r12\n\t"
                    "mov %%r13, r13\n\t"
                    "mov %%r14, r14\n\t"
                    "mov %%r15, r15\n\t"
        : "+m" (rax), "+m" (rbx), "+m" (rcx), "+m" (rdx), "+m" (rsi), "+m" (rdi), "+m" (r8), "+m" (r9), "+m" (r10), "+m" (r11), "+m" (r12), "+m" (r13), "+m" (r14), "+m" (r15)
        );

    asm volatile (
                    "pop %r15\n\t"
                    "pop %r14\n\t"
                    "pop %r13\n\t"
                    "pop %r12\n\t"
                    "pop %r11\n\t"
                    "pop %r10\n\t"
                    "pop %r9\n\t"
                    "pop %r8\n\t"
                    "pop %rdi\n\t"
                    "pop %rsi\n\t"
                    "pop %rdx\n\t"
                    "pop %rcx\n\t"
                    "pop %rbx\n\t"
                    "pop %rax\n\t" );

    printf("rax=%llu\nrbx=%llu\nrcx=%llu\nrdx=%llu\n", rax, rbx, rcx, rdx);
    printf("rsi=%llu\nrdi=%llu\nr8=%llu\nr9=%llu\n", rsi, rdi, r8, r9);
    printf("r10=%llu\nr11=%llu\nr12=%llu\nr13=%llu\n", r10, r11, r12, r13);
    printf("r14=%llu\nr15=%llu\n", r14, r15);
    
    return 0;
}
