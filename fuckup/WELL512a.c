/* ***************************************************************************** */
/* Copyright:      Francois Panneton and Pierre L'Ecuyer, University of Montreal */
/*                 Makoto Matsumoto, Hiroshima University                        */
/* Notice:         This code can be used freely for personal, academic,          */
/*                 or non-commercial purposes. For commercial purposes,          */
/*                 please contact P. L'Ecuyer at: lecuyer@iro.UMontreal.ca       */
/* ***************************************************************************** */
#include <stdio.h>
#include <sys/mman.h>

#define R 16
#define M1 13
#define M2 9

#define MAT0POS(t,v) (v^(v>>t))
#define MAT0NEG(t,v) (v^(v<<(-(t))))
#define MAT3NEG(t,v) (v<<(-(t)))
#define MAT4NEG(t,b,v) (v ^ ((v<<(-(t))) & b))

#define V0            STATE[state_i                   ]
#define VM1           STATE[(state_i+M1) & 0x0000000fU]
#define VM2           STATE[(state_i+M2) & 0x0000000fU]
#define VRm1          STATE[(state_i+15) & 0x0000000fU]
#define newV0         STATE[(state_i+15) & 0x0000000fU]

//minor change to make this solvable with z3 without crunching for a week
//#define newV1         STATE[state_i                   ] 
#define newV1         STATE[(state_i+10) & 0x0000000fU]

#define FACT 2.32830643653869628906e-10

static unsigned int state_i = 0;
//static unsigned int STATE[R];
unsigned int *STATE;
static unsigned int z0, z1, z2;

void InitWELLRNG512a (unsigned int *init){
   int j;
   state_i = 0;
   STATE = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   for (j = 0; j < R; j++)
     STATE[j] = init[j];
}

double WELLRNG512a (void){
  z0    = VRm1;
  z1    = MAT0NEG (-16,V0)    ^ MAT0NEG (-15, VM1);
  z2    = MAT0POS (11, VM2)  ;
  newV1 = z1                  ^ z2; 
  newV0 = MAT0NEG (-2,z0)     ^ MAT0NEG(-18,z1)    ^ MAT3NEG(-28,z2) ^ MAT4NEG(-5,0xda442d24U,newV1) ;
  state_i = (state_i + 15) & 0x0000000fU;
  //printf("STATE[%d]: %08x\n", state_i, STATE[state_i]);
  return ((double) STATE[state_i]) * FACT;
}

void PrintWELL()
{
	int i;
	for(i = 0; i < R; i++)
	{
		if((i != 0) && (i%4) == 0)
			printf("\n");
		printf("STATE[%02d]: %08x\t", i, STATE[i]);
	}
	printf("\n");

}
