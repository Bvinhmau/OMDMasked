#include "stdio.h"
#include "stdlib.h"
#include "omdsha256.c"
#include "math.h"
#include "RNGmacro.h"
#include <time.h>


struct timespec timer_start(){
    struct timespec start_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
    return start_time;
}

// call this function to end a timer, returning nanoseconds elapsed as a long
long timer_end(struct timespec start_time){
    struct timespec end_time;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_time);
    long diffInNanos = end_time.tv_nsec - start_time.tv_nsec;
    return diffInNanos;
}



 void main() {
int keysize = 32;
int noncesize = 32;
int messsize = 64	;
int asssize = 32;
clock_t begin, end;
double time_spent;
genDummy();


         unsigned char ke[keysize];

    unsigned char maskke[keysize] ;


       unsigned char nonce[noncesize] ;
   unsigned char maskNonce[noncesize] ;



      unsigned char block1[messsize] ;

    unsigned char  mask1[messsize] ;

    unsigned char  block2[asssize] ;

      unsigned char  mask2[asssize]	;
getDummyBlock(ke);
getDummyBlock(maskke);
getDummyBlock(nonce);
getDummyBlock(maskNonce);
getDummyBlock(block1);
getDummyBlock(mask1);
getDummyBlock(block2);
getDummyBlock(mask2);
     unsigned char  xored1[sizeof(mask1)];
          unsigned char  xored2[sizeof(mask2)];

      unsigned char  maskedK[sizeof(maskke)];
            unsigned char  maskedNonce[sizeof(nonce)];


//          unsigned char  maskedK[sizeof(maskke)];

    int i = 0;


    for( i = 0 ; i < sizeof(mask1) ; i++) {
      xored1[i] = mask1[i] ^ block1[i];
    }
      for( i = 0 ; i < sizeof(mask2) ; i++) {
      xored2[i] = mask2[i] ^ block2[i];
    }
     for( i = 0 ; i < sizeof(maskke) ; i++) {
      maskedK[i] = ke[i] ^ maskke[i];
    }

      for( i = 0 ; i < sizeof(maskedNonce) ; i++) {
      maskedNonce[i] = nonce[i] ^ maskNonce[i];
    }
//  for( i = 0 ; i < sizeof(maskke) ; i++) {
    //  maskedK[i] = maskke[i] ^ ke[i];
  //}

     unsigned char  w[sizeof(mask1)+8];
     unsigned char  w2[sizeof(mask1)+8];

const unsigned char *databl1=block1;
const unsigned char *datamask1=mask1;
const unsigned char *datamasked1=xored1;

const unsigned char *databl2=block2;
const unsigned char *datamask2=mask2;
const unsigned char *datamasked2=xored2;

const unsigned char *datak = ke;
const unsigned char *datamaskedk = maskedK;
const unsigned char *datamaskK = maskke;

const unsigned char *datan = nonce;
const unsigned char *mknonce = maskedNonce;
const unsigned char *mnonce  = maskNonce;
struct timespec vartime = timer_start();  // begin a timer called 'vartime'
sec_omdsha256_process(w2,
        datamaskedk , datamasked1,datamasked2, mknonce,

		 datamaskK, datamask1, datamask2,mnonce,

		 sizeof(block1),sizeof(block2)
		 , OMD_ENCRYPT);

long time_elapsed_nanos = timer_end(vartime);
printf("\n Spent for Sec Encryption  %ld\n", time_elapsed_nanos);


struct timespec vartimeSec = timer_start();

omdsha256_process(w, datak,
		  databl1,
sizeof(block1),
databl2, sizeof(block2),
		  datan,
		  OMD_ENCRYPT);

end = clock();

long time_elapsed_nanosSec = timer_end(vartimeSec);
printf("\n Spent for Encryption  %ld\n", time_elapsed_nanosSec);


//printf("ENCRYPTION \n");
//		       for(i = 0; i <  sizeof(w); i++)
  //      printf("%u ", w[i]);
   // printf("\n");
//printf("\n");
//printf("SECENCRYPTION \n");
//		       for(i = 0; i <  sizeof(w2); i++)
 //       printf("%u ", w2[i]);
  //  printf("\n");


  unsigned char  maskCiph[sizeof(w)] ;
getDummyBlock(maskCiph);
    unsigned char  maskedCiph[sizeof(maskCiph)] ;
      for( i = 0 ; i < sizeof(maskCiph) ; i++) {
      maskedCiph[i] = w2[i] ^ maskCiph[i];
    }


const unsigned char *mkciph = maskedCiph;
const unsigned char *mciph  = maskCiph;
const unsigned char *ciph  = w;

     unsigned char  w3[sizeof(mask1)];
     unsigned char  w4[sizeof(mask1)];



sec_omdsha256_process(w3,
        datamaskedk , mkciph,datamasked2, mknonce,

		 datamaskK, mciph, datamask2,mnonce,

		 sizeof(w),sizeof(block2)
		 , OMD_DECRYPT);










omdsha256_process(w4, datak,
		  ciph,
sizeof(w),
databl2, sizeof(block2),
		  datan,
		  OMD_DECRYPT);



printf(" \n DECRYPTION \n");
		       for(i = 0; i <  sizeof(w4); i++)
        printf("%u ", w4[i]);
    printf("\n");
printf("\n");


printf("SEC DECRYPTION \n");
		       for(i = 0; i <  sizeof(w3); i++)
        printf("%u ", w3[i]);
    printf("\n");
printf("\n");



  const unsigned char correct[] = {
      218,128,128,128,0,0,229,0,
      0,40,0,55,24,0,0,0,
      0,24,0,124,0,0,123,0,
      0,0,0,47,0,128,111,12,12,14,45,1,124,98,24
   };


}




