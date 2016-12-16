/**
A Set of Macro that handle the basic Random number generation
 */
#include "stdio.h"
#include "stdlib.h"

// Will be used later to avoid launch on system where urandom is not avaiable
#ifdef __linux__
	#define test() printf("Launching on linux\n")
	
#else
        #define test() printf("Launching on UNDEFINED\n")
	
#endif

// 1 if the random number should always be refreshed, and result in terrible performance. Should be only set to one for testing purposes
#define ISFULLRANDOM 0
#define DUMMYGENERATION 1 // 1 if you want to get your random number from a pregenerated array
// Return a random of the size of the input
#define RNG(random) fread (&random, sizeof(random), 1, urandom)\
// Return an array, with each of it cell randomly initialized
#define RNGBlock(random) fread (&random, sizeof(random)*sizeof(random[0]), 1, urandom)\

#define CloseRNG() fclose(urandom)\

#define SetRNG()\
	static FILE *urandom;\
	uint32_t  randint ;\
	urandom = fopen ("/dev/urandom", "r");\
	if (urandom == NULL) {\
	fprintf (stderr, "Cannot open /dev/urandom!\n");\
	exit (1);\
	}\



#define setNewRand()\
({\
memset(InitializedRNG, 0,  sizeof(InitializedRNG)* sizeof(InitializedRNG[0]));\
})
#define generateRand(rand,id)\
({\
	if(ISFULLRANDOM == 1){\
		getFullRand(rand);\
	}\
	else {\
	  getRand(rand,id);\
	}\
})
#define getFullRand(rand) \
({\
            printf("fresh ");\
	    SetRNG();\
            RNG(rand);\
	    CloseRNG();\
 })

#define getFullRandBlock(rand) \
({\
            printf("fresh block ");\
	    SetRNG();\
            RNGBlock(rand);\
	    CloseRNG();\
 })
// Set to return a random Int32_t
#define getRand(rand,i) \
({\
    if (i >=0){\
        if (InitializedRNG[i] == 0) {\
		if(DUMMYGENERATION==1){\
			getDummyInt32(listRNG[i]);\
		}\
		else{\
        	    getFullRand(listRNG[i]);\
		}\
            InitializedRNG[i] =1;\
        }\
    }\
    rand = listRNG[i];\
 })


#define getRandHashBlock(rand,i) \
({\
    if (i >=0){\
        if (InitializedRNG[i] == 0){\
	if(DUMMYGENERATION==1){\
		getDummyBlock(listHashBlockRNG[i]);\
	}\
	else{\
            getFullRandBlock(listHashBlockRNG[i]);\
	}\
            InitializedRNG[i] =1;\
        }\
    }\
    memcpy (rand, listHashBlockRNG[i], sizeof(listHashBlockRNG[i]));\
 })
#define getRandMessageBlock(rand,i) \
({\
    if (i >=0){\
        if (InitializedRNG[i] == 0) {\
	if(DUMMYGENERATION==1){\
		getDummyBlock(listMessageBlockRNG[i]);\
	}\
	else{\
            getFullRandBlock(listMessageBlockRNG[i]);\
	}\
            InitializedRNG[i] =1;\
        }\
    }\
    memcpy (rand, listMessageBlockRNG[i], sizeof(listMessageBlockRNG[i]));\
 })



#define getDummyInt32(rand){\
rand = 0;\
char buffer[4];\
strncpy(buffer, DummyRandoms+indexDummy, sizeof(buffer));\
indexDummy = indexDummy + sizeof(buffer);\
if(indexDummy > 10000000) {\
printf("\n out of Dummy \n");\
}\
memcpy(&rand, buffer, 4);\
}

#define getDummyBlock(rand){\
strncpy(rand, DummyRandoms+indexDummy, sizeof(rand));\
indexDummy = indexDummy + sizeof(rand);\
if(indexDummy > 10000000) {\
printf("\n out of Dummy \n");\
}\
}

#define  genDummy()\
({ \
indexDummy = 0;\
srand(1234567+ time(NULL));\
int j = 0;\
for (j = 0 ; j < 10000000; j++ ){\
	DummyRandoms[j] = rand() % 256;\
	}\
})\

static int indexDummy ;
unsigned char 	DummyRandoms[10000000];\
// Index used until 35!
static int InitializedRNG[100]; // Array used to check if the random number i has been initilized
static uint32_t listRNG[100]; // Array used to eventually save the value of a random number
static hashblock listHashBlockRNG[100]; // Array used to eventually save the value of a random hashblock
static hashblock listMessageBlockRNG[100]; // Array used to eventually save the value of a random hashblock
