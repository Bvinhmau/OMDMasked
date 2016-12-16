/**
 * The implementation of omdsha256 mode
 */
#include "omdsha256.h"
#include <string.h>
#include <math.h>
#include "RNGmacro.h"

#define SecAnd(z,xm,ym,r,s,u) \
({\
	(z) = ((u) ^((xm) & (ym)));\
	(z) = ((z)^( (xm) & (s)));\
	(z) = ((z)^( (r) & (ym)));\
	(z) = ((z)^( (r) & (s)));\
})


#define SecOr(z,xm,ym,r,s,u)\
({\
	SecAnd((z),(~xm),(~ym),(r),(s),(u));\
	z = ~z;\
 })

#define SecXor(z,xm,ym,r,s)  \
({\
	(z) = ((xm) ^ (ym));\
	(z) = ( (z) ^ (s) );\
})



#define SecShift(z,xm,r,u,j) \
({\
((z) = (xm) ) ;\
((z) = z << (j) );\
((z) = ((u) ^(z)));\
(z) = ((z) ^ ((r) << (j))); \
})


#define SecShiftR(z,xm,r,u,j) \
({\
((z) = (xm) ) ;\
((z) = z >> (j) );\
((z) = ((u) ^(z)));\
(z) = ((z) ^ ((r) >> (j))); \
})

void
sec_xor_block (hashblock res, const hashblock in1, const hashblock in2, const hashblock mask1, const hashblock mask2)
{
    unsigned int i;

    for (i = 0; i < OMD_n ; i++)
       {
	SecXor(res[i],in1[i],in2[i],mask1[i],mask2[i]);
       }
}

void refreshMask(hashblock input, const hashblock inputmask , const hashblock outputmask) {
    uint32_t i = 0;
    for (i = 0; i < OMD_n; i++) {
	input[i] = input[i] ^ outputmask[i] ;
	input[i] = input[i] ^inputmask[i];

    }
}
void
sec_double_block (hashblock res, const hashblock in, const hashblock mask)
{
    unsigned int i;
    /* create bitmask from msb using signed shift */
    unsigned char carry = (in[0]) & 0x80;
    unsigned char maskCarry = (mask[0] )& 0x80;
    unsigned char tempmask1 ; 
	unsigned char tempmask2 ;
getRand(tempmask1 ,26);
getRand(tempmask2 ,27);
     unsigned char temp4 = 0;
	 unsigned char temp3 = 0;
	 unsigned char temp2 = 0;
	 unsigned char temp1 = 0;
	 unsigned char temp = 0;



    for (i = 0; i < OMD_n-1; i++)
       {

	  /* shift with carry from next block */

	SecShift(temp1,in[i],mask[i],tempmask1,1);
	SecShiftR(temp2,in[i+1],mask[i+1],tempmask2,7);
	SecOr(res[i],temp1,temp2,tempmask1,tempmask2,mask[i]);
}

	SecShift(res[OMD_n -1],in[OMD_n -1],mask[OMD_n -1],tempmask1,1);
	res[OMD_n -1] = res[OMD_n -1]^mask[OMD_n -1];
	res[OMD_n -1] = res[OMD_n -1] ^ tempmask1; // Remove the influence of the temp mask and restore the original mask



    	/* xor P(x) if msb */
	unsigned char  carried1 = 0;
	unsigned char carried2 = 0 ;

    SecShiftR(carried2,carry, maskCarry,tempmask1,5);

	SecXor(temp,res[OMD_n -2],carried2,mask[OMD_n -2],tempmask1);
    res[OMD_n -2] = temp;

	SecShiftR(temp3,carry,maskCarry,tempmask2,2);
	SecShiftR(temp2,carry,maskCarry,tempmask1,7);

  	SecXor(temp4,temp3,temp2,tempmask2,tempmask1);

	SecXor(carried1,temp4,carried2,tempmask2,tempmask1);
	SecXor(temp1,res[OMD_n -1],carried1,mask[OMD_n -1],tempmask2);

	res[OMD_n -1] = temp1;

}




void
sec_triple_block (hashblock res, const hashblock in, const hashblock mask)
{
    unsigned int i;
    /* create bitmask from msb using signed shift */
    unsigned char carry = in[0] & 0x80;
    unsigned char maskCarry = (mask[0])& 0x80;

	 unsigned char temp1 = 0;
	unsigned char temp2 = 0;
unsigned char temp3 = 0;
	unsigned char tempmask1 ; 
	unsigned char tempmask2 ;
	unsigned char tempmask3 ;
getRand(tempmask1 ,28);
getRand(tempmask2 ,29);
getRand(tempmask3 ,30);
    for (i = 0; i < OMD_n -1; i++)
       {

	  /* shift with carry from next block */




	//SecShift(z,xm,r,u,j)
	SecShift(temp1,in[i],mask[i],tempmask1,1);
	SecShiftR(temp2,in[i+1],mask[i+1],tempmask2,7);
	SecOr(temp3,temp1,temp2,tempmask1,tempmask2,tempmask3);
    SecXor(res[i], in[i], temp3, mask[i], tempmask3);

       }

	SecShift(temp1,in[OMD_n-1],mask[OMD_n-1],tempmask1,1);
	temp2 = in[OMD_n-1]; // Used to avoid problem in XOR macro
	SecXor(res[OMD_n-1],temp2,temp1,mask[OMD_n-1],tempmask1);


		// Refresh a each step ?
	 unsigned char temp4 = 0;
	 unsigned char temp = 0;


    	/* xor P(x) if msb */

	unsigned char carried2 = 0 ;
	SecShiftR(carried2,carry,maskCarry,tempmask2,5);


	unsigned char  carried1 = 0;


	SecXor(temp,res[OMD_n -2],carried2,mask[OMD_n -2],tempmask2);
	res[OMD_n -2] = temp;

	SecShiftR(temp3,carry,maskCarry,tempmask1,2);
	SecShiftR(temp2,carry,maskCarry,tempmask3,7);

  	SecXor(temp4,temp3,temp2,tempmask1,tempmask3);

	SecXor(carried1,temp4,carried2,tempmask1,tempmask2);
	SecXor(temp1,res[OMD_n -1],carried1,mask[OMD_n -1],tempmask1);

	res[OMD_n -1] = temp1;

}
void
calc_L_i (hashblock l, const hashblock lzero, unsigned int i)
{
   /* i==0 => l=lzero */



   if (i == 0)
      {
	 memcpy(l, lzero, OMD_n );
	 return;
      }


   double_block(l,lzero);

   /* L[i]=2.L[i-1] */
   while (--i)
      {
	 double_block(l,l);
      }
}



void sec_calc_L_i (hashblock l, const hashblock lzero, const hashblock masklzero, unsigned int i)
{
   /* i==0 => l=lzero */




   if (i == 0)
      {

	 memcpy(l, lzero, OMD_n );

	 return;
      }


   sec_double_block(l,lzero,masklzero);

   /* L[i]=2.L[i-1] */
   while (--i) {


	 sec_double_block(l,l,masklzero);
      }

}
void sec_increment_masking_associated_data (hashblock delta_n,
                   const hashblock delta_o,const hashblock lzero,
				   const hashblock maskDelta_o, const hashblock maskLzero
				   , int i)
{
   hashblock l;


   /* \delta_{i, 0} = \delta_{i-1, 0} ^ L[ntz(i)]  */
   sec_calc_L_i (l, lzero, maskLzero , ntz(i));

   sec_xor_block (delta_n, l, delta_o, maskLzero, maskDelta_o );



}
void
sec_increment_masking_message (hashblock delta_n,
                               const hashblock delta_o,const hashblock lzero,
                               const hashblock maskdelta_o , const hashblock masklzero, int i)
{
   hashblock l;

   if (i < 1)
      {
	 return;
      }

   /* \delta_{N, i, 0} = \delta_{N, i-1, 0} ^ L[ntz(i)]  */

   sec_calc_L_i(l, lzero, masklzero ,ntz(i));



   sec_xor_block(delta_n, delta_o, l,maskdelta_o,masklzero);
   // refresh the masj to avoid
   // output with mask maskdelta_o



}
void
increment_masking_message (hashblock delta_n, const hashblock delta_o,
			   const hashblock lzero, int i)
{
   hashblock l;

   if (i < 1)
      {
	 return;
      }

   /* \delta_{N, i, 0} = \delta_{N, i-1, 0} ^ L[ntz(i)]  */
   calc_L_i(l, lzero, ntz(i));



   xor_block(delta_n, delta_o, l);



}
//Sec_sha256_comp (hashblock res, const hashblock hash, const void *in , const void *inmask, const hashblock hashmask , const void *outmask)
void
sec_key_func (hashblock res, const hashblock hash, const hashblock key,
	  const hashblock message, const hashblock maskHash, const hashblock maskKey, const hashblock maskMessage)
{
   messageblock glue;
   messageblock maskglue;

   memcpy (glue, key, OMD_n );
   /* K,M -> K||M */
   memcpy (&glue[OMD_n] , message, OMD_n );



   memcpy (maskglue, maskKey, OMD_n );
   /* K,M -> K||M */
   memcpy (&maskglue[OMD_n] , maskMessage, OMD_n );
    int i = 0;



   for (i = 0; i < OMD_n ; i++) {
     //   printf("%u,", outmask[i]) ;
   }
   /*call the underlying compression function*/
    //SEC_OMD_COMP (res, hash, glue);

   SEC_OMD_COMP (res, hash, glue , maskHash, maskglue);
  //  printf("\n derp : %u n " , res[0] ^outmask[0]);
}
void
sec_final_masking_associated_data (hashblock delta_n,
                                   const hashblock delta_o, const hashblock lstar,
                                   const hashblock maskDelta_o, const hashblock maskLstar)
{
   /* \delta_{i, 0} = \delta_{i-1, 0} ^ L[ntz(i)]  */
   sec_xor_block(delta_n,delta_o,lstar,maskDelta_o,maskLstar);
}
void
xor_block (hashblock res, const hashblock in1, const hashblock in2)
{
    unsigned int i;
    for (i = 0; i < OMD_n ; i++)
       {
	  res[i] = in1[i] ^ in2[i];
       }
}

void
double_block (hashblock res, const hashblock in)
{
    unsigned int i;
    /* create bitmask from msb using signed shift */
    unsigned char carry = in[0] & 0x80;

    for (i = 0; i < OMD_n-1; i++)
       {
	  /* shift with carry from next block */
	  res[i] = (in[i] << 1) | (in[i+1] >> 7);
       }

    res[OMD_n -1] = (in[OMD_n -1] << 1);

	if(carry) {
    	/* xor P(x) if msb */
    	res[OMD_n -2] = res[OMD_n -2] ^ 0x04;
    	/* shift and xor P(x) if msb */
    	res[OMD_n -1] = res[OMD_n -1] ^ 0x25;
    }
}

void
triple_block (hashblock res, const hashblock in)
{
    unsigned int i;
    /* create bitmask from msb using signed shift */
    unsigned char carry = in[0] & 0x80;

    for (i = 0; i < OMD_n -1; i++)
       {
	  /* shift and xor */
	  res[i] = in[i] ^ ((in[i] << 1) | (in[i+1] >> 7));
       }

    res[OMD_n -1] = in[OMD_n -1] ^ (in[OMD_n -1] << 1);

	/* xor P(x) if msb */
	if(carry) {
    	res[OMD_n -2] = res[OMD_n -2] ^ 0x04;
	    res[OMD_n -1] = res[OMD_n -1] ^ 0x25;
    }
}

void
l2b (hashblock bit_string, int value)
{
   int ptr = value*8;
   unsigned int i = OMD_n;

   memset(bit_string, 0x00, OMD_n );

   while (i--)
      {   /* write the bytes of value into tau */
	 bit_string[i] = ptr & 0xff;
	 ptr >>= 8;
      }
}

void
key_func (hashblock res, const hashblock hash, const hashblock key,
	  const hashblock message)
{
   messageblock glue;

   memcpy (glue, key, OMD_n );
   /* K,M -> K||M */
   memcpy (&glue[OMD_n] , message, OMD_n );

   /*call the underlying compression function*/
  OMD_COMP (res, hash, glue);

}


int
ntz (int v)
{
   int c;

   /* Set v's trailing 0s to 1s and zero rest */
   v = (v ^ (v - 1)) >> 1;

   for (c = 0; v; c++)
      {
	 v >>= 1;
      }

   return c;
}



void
final_masking_message (hashblock delta_n, const hashblock delta_o,
		       const hashblock lstar, int j)
{
   hashblock l;

   switch (j)
      {
      case 1:
	 /* \delta_{N, i, 1} = \delta_{N, i, 0} ^ 2*L_*  */

	 double_block (l, lstar);
	 xor_block (delta_n, delta_o, l);
	 break;

      case 2:
	 /* \delta_{N, i, 2} = \delta_{N, i, 0} ^ 3*L_*  */
	 triple_block (l, lstar);

	 xor_block (delta_n, delta_o, l);

	 break;
      }
}

void
sec_final_masking_message (hashblock delta_n,
                           const hashblock delta_o,const hashblock lstar,
                           const hashblock maskDelta_o , const  hashblock maskLstar ,
                           int j)
{
   hashblock l;


   switch (j)
      {
      case 1:
	 /* \delta_{N, i, 1} = \delta_{N, i, 0} ^ 2*L_*  */



	 sec_double_block (l, lstar, maskLstar);
    sec_xor_block(delta_n,delta_o,l,maskDelta_o,maskLstar);
      // refreshing the mask
	 break;

      case 2:
	 /* \delta_{N, i, 2} = \delta_{N, i, 0} ^ 3*L_*  */
	 sec_triple_block (l, lstar, maskLstar);

    sec_xor_block(delta_n,delta_o,l,maskDelta_o,maskLstar);
      // refreshing the mask

	 break;
      }
}



void
increment_masking_associated_data (hashblock delta_n, const hashblock delta_o,
				   const hashblock lzero, int i)
{
   hashblock l;

   /* \delta_{i, 0} = \delta_{i-1, 0} ^ L[ntz(i)]  */
   calc_L_i (l, lzero, ntz(i));
   xor_block (delta_n, delta_o, l);
}

void
final_masking_associated_data (hashblock delta_n, const hashblock delta_o,
			       const hashblock lstar)
{
   /* \delta_{i, 0} = \delta_{i-1, 0} ^ L[ntz(i)]  */
   xor_block (delta_n, delta_o, lstar);
}

void
hash (hashblock taga, const hashblock key, const unsigned char *ad,
      unsigned long long int adlen)
{
   hashblock lstar, lzero;
   hashblock delta;
   hashblock left, right;
   hashblock xor_res, key_func_res;
   hashblock taures;
   unsigned int  modlen;
   long long int i, l;
   size_t b;

   /* CHANGE FROM V1 TO V2 HERE*/
   /* L* = F_K(0^n, <tau>_m) */
   l2b (taures, OMD_tau);
   key_func (lstar, block0s, key, taures);

   /* L[0] = 4.L* */

   double_block (lzero, lstar);
   double_block (lzero, lzero);

   /*b = n+m*/
   b = OMD_n + OMD_m;

   /* A_1 || A_2 ··· A_{l−1} || A_l = A, where |A_i| = b for 1 ≤ i ≤ l−1
      and |A_l| ≤ b */
   /* l=ceil(adlen/b) */
   l = (adlen + b - 1)/b;

   /* Tag_a = 0^n  */
   memset (taga, 0x00, OMD_n);
   /* If AD="" => Tag_a = 0^n */
   if (adlen == 0)
      {
	 return;
      }

   /* \bar{\delta}_{0,0} = 0^n */
   memset (delta, 0x00, OMD_n);

   /** for i = 1 to l-1 **/
   /**********************/
   for (i = 0; i < l-1; i++)
      {

	 /*  \bar{\delta}_{i, 0} =  \bar{\delta}{i-1, 0} ^ L[ntz(i)]  */

	 increment_masking_associated_data (delta, delta, lzero, i+1);

	 /* Left = A_l[b-1...m]; */
	 memcpy (left, &ad[i*b],  OMD_n);
	 /* Right = A_l[m-1...0]  */
	 memcpy (right,&ad[i*b+OMD_n],OMD_m);

	 /* Tag_a = Tag_a ^ F_K(Left ^ \delta_{i, 0}, right) */
	 xor_block (xor_res, delta, left);
	 key_func (key_func_res, xor_res, key, right);
	 xor_block (taga, taga, key_func_res);
      }
   /**************************/
   /******* endfor ***********/

   /* here adlen!=0, we process last ad block*/

   modlen = adlen%b;

   /* |A_l| = b then */
   if (modlen == 0)
      {
	 /* last mask = \bar{\delta}{l,0}  */
	 increment_masking_associated_data(delta, delta, lzero,l);

	 memcpy (left, &ad[(l-1)*b],      OMD_n);
	 memcpy (right,&ad[(l-1)*b+OMD_n],OMD_m);
      }
   /* |A_l| < b then */
   else
      {
	 /* last mask = \bar{\delta}{l-1,1}  */
	 final_masking_associated_data (delta, delta, lstar);

	 memset (left , 0x00, OMD_n );
	 memset (right, 0x00, OMD_m );

	 memcpy (left, &ad[(l-1)*b], (modlen < OMD_n ? modlen : OMD_n));
	 memcpy (right, &ad[(l-1)*b+OMD_n], (modlen < OMD_n
					     ? 0
					     : modlen - OMD_n));

	 if (modlen < OMD_n)
	    /* pad last block */
	    left[modlen]= 0x80;
	 else
	    right[modlen-OMD_n]=0x80;
   }

   /* Tag_a = Tag_a ^ F_K(Left ^ \delta_{l, 0 or 1}, right) */
   xor_block(xor_res, delta, left);
   key_func(key_func_res, xor_res, key, right);
   xor_block(taga, taga, key_func_res);
}

int
omdsha256_process(unsigned char *data, const unsigned char* key,
                  const unsigned char *data_process,
                  unsigned long long int data_processlen,
                  const unsigned char *ad, unsigned long long int adlen,
                  const unsigned char *nonce,
                  const enum mode encrypting)
{
   hashblock key_block;
   hashblock lstar, lzero;
   hashblock nonce_block;
   hashblock delta;
   hashblock h;
   hashblock res, res2;
   hashblock taures;
   hashblock taga, tage, tag, tag_prime;
   hashblock xor_res;
   unsigned int statedelta, data_process_modlen;
   long long int i, l = 0;

   /* if |K| > n => return -1  */
   if (10 > OMD_k || OMD_k > OMD_n)
      return -1;

   /* if |N| > n-1 => return -1 */
   if ((12 > OMD_lnonce) || (OMD_lnonce > OMD_n-1))
      return -1;

   /* if |C| < tau => return -1 */
   if ((encrypting == OMD_DECRYPT) && (data_processlen < OMD_tau))
      return -1;

   memset (key_block, 0x00, OMD_n);
   memcpy (key_block, key, OMD_k);



   if (encrypting == OMD_ENCRYPT)
      {
      /* M_1 || M_2 ··· M_{l−1} || M_l = M, where |M_i| = m for 1 ≤ i ≤ l−1
	 and |M_l| ≤ m */
	 /* l = ceil(|M|/m) */
	 l = (data_processlen + (OMD_m-1))/OMD_m;
      }
   else if (encrypting == OMD_DECRYPT)
      {
      /* C_1 || C_2 ··· C_{l−1} || C_l || Tag = \mathbb{C},
	 where |C_i| = m for 1 ≤ i ≤ l−1 and |C_l| ≤ m and |Tag| = \tau*/
      data_processlen = data_processlen - OMD_tau;
      /* l = ceil(|C|/m) */
      l = (data_processlen +(OMD_m-1))/OMD_m;
      }


   /* Tag_a computed here to handle a=c overlap */
   /* Tag_a = HASH_k(ad)  */
   hash(taga, key_block, ad, adlen);



   /* CHANGE FROM V1 TO V2 HERE*/
   /* L* = F_K(0^n, <tau>_m) */
   l2b (taures, OMD_tau);


   key_func (lstar, block0s, key_block, taures);

   /* L[0] = 4.L* */


   double_block (lzero, lstar);   /* 2.L_* */


   /* L[0] = 4.L* */
   double_block (lzero, lzero);   /* 2.(2.L_*) */

   // printf("2lzero: \n");
   // for(i = 0; i <  sizeof(lzero); i++)
       // printf("%u ", lzero[i] );
   // printf("\n");

   /* pad nonce */
   memset (nonce_block, 0x00, OMD_n);
   memcpy (nonce_block, nonce, OMD_lnonce);

   nonce_block[OMD_lnonce] = 0x80;

   /* \delta{N,0,0} = F_K(N || 10^{n-1-|N|}, 0^m  */
   key_func (delta, nonce_block, key_block, block0s);


   /* H = 0^n */

   memset (h, 0x00, OMD_n );

   /* \delta{N,1,0} = \delta{N,0,0} ^ L[ntz(1)]  */
   increment_masking_message (delta, delta, lzero, 1);

   /* H = F_K(H ^ \delta_{N, 1, 0}, <tau>_m)  */
   xor_block (h, h, delta);



   key_func (h, h, key_block, taures);

   /* for i = 1 to l-1 do  */
   /************************/
   for (i = 0; i < l-1; i++)
      {
	 /* C_i = H ^ M_i */
	 /* M_i = H ^ C_i */
	 memcpy(res,&data_process[i*OMD_m],OMD_m);
	 xor_block(res2, h, res);


	 memcpy(&data[i*OMD_m],res2,OMD_m);





	 /* \delta_{N, i+1, 0} = \delta{N, i, 0} ^ L[ntz(i+1)]  */
	 increment_masking_message(delta, delta, lzero, i+2);

	 /* H = F_K(H ^ \delta{N, i, 0}, M_i) */

	 xor_block(xor_res, delta, h);

	 if (encrypting == OMD_ENCRYPT)
	    /* res  = M_i */
	    key_func(h, xor_res, key_block, res);
	 else if (encrypting == OMD_DECRYPT)
	    /* res2 = M_i */
	    key_func(h, xor_res, key_block, res2);
      }

   /************************/
   /******** endfor ********/


   /* |M|>0 */
   if (data_processlen!=0)
      {
	 /* C_l = H ^ M_l */
	 /* M_l = H ^ C_l *//* |M_l| = m then */
	 data_process_modlen = data_processlen%OMD_m;
	 memset (res,0x00,OMD_m);
	 memcpy(res, &data_process[(l-1)*OMD_m], (data_process_modlen==0
						  ? OMD_m
						  : data_process_modlen));


	 xor_block(res2, h, res);



	 memcpy(&data[(l-1)*OMD_m], res2, (data_process_modlen==0
					   ? OMD_m : data_process_modlen));

      /* if |M_\ell|=m */
      if (data_process_modlen == 0)
         statedelta = 1;
      /* else if |M_\ell|<m*/
      else
         statedelta = 2;

      /* \delta{N, l, 1} = \delta{N, l, 0} ^ (2 or 3)*L_* */


      final_masking_message(delta, delta, lstar, statedelta);
      /* Tag_e = F_K(H ^ \delta{N, l, 1}, M_l)  */

      xor_block(h, h, delta);

      if (encrypting == OMD_ENCRYPT)
	 {
	    /* if |M_\ell|<m, we pad*/
	    if (statedelta==2)
	       res[data_process_modlen]=0x80;


	    key_func(tage, h, key_block, res);        /* res  = M_i */

	 }
      else if (encrypting == OMD_DECRYPT)
	 {
	    if(statedelta==2)
	       {
		  /* if |M_\ell|<m, we pad*/
		  res2[data_process_modlen]=0x80;
		  memset(&res2[data_process_modlen+1], 0x00,
			 OMD_m - data_process_modlen - 1);
    int j = 0;


	       }

         key_func(tage, h, key_block, res2);      /* res2 = M_i */
	 }

      }
   /* |M| = 0 => tage = H */
   else
      {
	 memcpy(tage,h,OMD_n);
      }



   /* Tag = (Tag_e ^ Tag_a)[n-1 ... n- tau]  */
   xor_block(tag, taga, tage);



   /*ENCRYPT => output tag and return 0*/
   if (encrypting == OMD_ENCRYPT)
      {
	 memcpy (&data[data_processlen], tag, OMD_tau);

	 return 0;
      }

   /* or check tag */
   memcpy(tag_prime, &data_process[data_processlen], OMD_tau);

   if (memcmp (tag,tag_prime,OMD_tau) == 0)
      {

	 return 0;
      }

   return -1;
}

void
secHash (hashblock taga, const hashblock key, const unsigned char *ad,const hashblock maskKey, const unsigned char *maskAd,
      unsigned long long int adlen, hashblock outputMask)
{
   hashblock lstar, lzero;
   hashblock delta;
   hashblock left, right;
   hashblock maskleft, maskright;
   hashblock xor_res, key_func_res;
   hashblock taures;

    hashblock maskDelta ;


   unsigned int  modlen;
   long long int i, l;
   size_t b;

   /* CHANGE FROM V1 TO V2 HERE*/
   /* L* = F_K(0^n, <tau>_m) */
   l2b (taures, OMD_tau);

   hashblock maskBlock0s ;
      hashblock maskTaures ;
       hashblock  maskTaga ;

getRandHashBlock(maskBlock0s ,31);
getRandHashBlock(maskTaures ,32);
getRandHashBlock(maskTaga ,33);
getRandHashBlock(maskDelta ,34);
getRandHashBlock(maskleft ,34);
getRandHashBlock(maskright ,35);
   hashblock maskedBlock0s = "";
      hashblock maskedTaures = "";

    xor_block (maskedBlock0s, block0s, maskBlock0s); 
    xor_block (maskedTaures, taures, maskTaures);

    sec_key_func (lstar, maskedBlock0s, key, maskedTaures, maskBlock0s, maskKey, maskTaures);

   //key_func (lstar, block0s, key, taures);
   /* L[0] = 4.L* */


   sec_double_block (lzero, lstar, maskBlock0s );
   sec_double_block (lzero, lzero, maskBlock0s);

   /*b = n+m*/
   b = OMD_n + OMD_m;

   /* A_1 || A_2 ··· A_{l−1} || A_l = A, where |A_i| = b for 1 ≤ i ≤ l−1
      and |A_l| ≤ b */
   /* l=ceil(adlen/b) */
   l = (adlen + b - 1)/b;

   /* Tag_a = 0^n  */
   memset (taga, 0x00, OMD_n);
    xor_block(taga,taga,maskTaga); 
   /* If AD="" => Tag_a = 0^n */
   if (adlen == 0)
      {
	 return;
      }

   /* \bar{\delta}_{0,0} = 0^n */
   memset (delta, 0x00, OMD_n);


   xor_block(delta,delta,maskDelta); // initial masking of delta;


   /** for i = 1 to l-1 **/
   /**********************/
   for (i = 0; i < l-1; i++)
      {



	 /*  \bar{\delta}_{i, 0} =  \bar{\delta}{i-1, 0} ^ L[ntz(i)]  */
	     sec_increment_masking_associated_data (delta,
                                           delta, lzero,
                                           maskDelta, maskBlock0s
                                           , i+1);

	 /* Left = A_l[b-1...m]; */
	 memcpy (left, &ad[i*b],  OMD_n);
    memcpy (maskleft, &maskAd[i*b],  OMD_n);

	 /* Right = A_l[m-1...0]  */
	 memcpy (right,&ad[i*b+OMD_n],OMD_m);
	 memcpy (maskright,&maskAd[i*b+OMD_n],OMD_m);


//maskBlock0s
	 /* Tag_a = Tag_a ^ F_K(Left ^ \delta_{i, 0}, right) */
	 sec_xor_block(xor_res,delta,left,maskDelta,maskleft);
	 sec_key_func(key_func_res,xor_res,key,right,
              maskDelta,maskKey,maskright);
	 sec_xor_block(taga,taga,key_func_res,maskTaga,maskDelta);
      }
   /**************************/
   /******* endfor ***********/

   /* here adlen!=0, we process last ad block*/

   modlen = adlen%b;
    // As adlen "public", not a sensible condition
   /* |A_l| = b then */
   if (modlen == 0)
      {


	 /* last mask = \bar{\delta}{l,0}  */
	 sec_increment_masking_associated_data (delta,
                                           delta, lzero,
                                          maskDelta, maskBlock0s
                                          , l);




	 memcpy (left, &ad[(l-1)*b],      OMD_n);
	 memcpy (right,&ad[(l-1)*b+OMD_n],OMD_m);


	 memcpy (maskleft, &maskAd[(l-1)*b],      OMD_n);
	 memcpy (maskright,&maskAd[(l-1)*b+OMD_n],OMD_m);
      }

   /* |A_l| < b then */
   else
      {


	 /* last mask = \bar{\delta}{l-1,1}  */
	 sec_final_masking_associated_data ( delta,
                                   delta, lstar,
                                   maskDelta, maskBlock0s
                                   );



	 memset (left , 0x00, OMD_n );
	 memset (right, 0x00, OMD_m );

	 memcpy (left , maskleft, OMD_n );
	 memcpy (right, maskright, OMD_m );

	 memcpy (left, &ad[(l-1)*b], (modlen < OMD_n ? modlen : OMD_n));
	 memcpy (right, &ad[(l-1)*b+OMD_n], (modlen < OMD_n
					     ? 0
					     : modlen - OMD_n));

     memcpy (maskleft, &maskAd[(l-1)*b], (modlen < OMD_n ? modlen : OMD_n));
	 memcpy (maskright, &maskAd[(l-1)*b+OMD_n], (modlen < OMD_n
					     ? 0
					     : modlen - OMD_n));

	 if (modlen < OMD_n){
	    /* pad last block */
	    left[modlen]= 0x80 ^ maskleft[modlen];
	 }

	 else {
	    right[modlen-OMD_n]=0x80 ^ maskright[modlen-OMD_n];

	 }

   }


   /* Tag_a = Tag_a ^ F_K(Left ^ \delta_{l, 0 or 1}, right) */
   sec_xor_block(xor_res,delta,left,maskDelta,maskleft);
   sec_key_func(key_func_res,
                xor_res,key,right,
                maskDelta, maskKey,maskright
                );
   sec_xor_block(taga, taga, key_func_res,maskTaga,maskDelta);
   xor_block(taga,taga,outputMask);
   xor_block(taga,taga,maskTaga);

}

//TODO ORDER OF INPUT INCOHERENT
sec_omdsha256_process(unsigned char *data,

          const unsigned char* key,
		  const unsigned char *data_process,
		  const unsigned char *ad,
		  		  const unsigned char *nonce,


		  const unsigned char* maskKey,
           const unsigned char *maskData_process,
         const unsigned char *maskAd,
         const unsigned char *masknonce,



		  unsigned long long int data_processlen,
		  unsigned long long int adlen,

		  const enum mode encrypting)
{
   hashblock key_block;
   hashblock maskKey_block;

   hashblock lstar, lzero;
   hashblock nonce_block;
      hashblock maskNonce;

   hashblock delta;
   hashblock h;
   hashblock res, res2;
   hashblock maskRes, maskRes2;
   hashblock taures;
   hashblock taga, tage, tag, tag_prime;
   hashblock maskTag_prime;
   hashblock xor_res;
setNewRand();
 hashblock maskTage =    ""; 
   hashblock maskHash ="";
   hashblock maskDelta = "";
   hashblock maskH =   "";
   hashblock maskTau =  "";
   hashblock temp_maskNonce =  "";
    hashblock temp_maskRes = ""; 

  messageblock maskBlock0 =   ""; 

getRandHashBlock(maskTage,18);
getRandHashBlock(maskHash,19);
getRandHashBlock(maskDelta,20);
getRandHashBlock(maskH,21);
getRandHashBlock(maskTau,22);
getRandHashBlock(temp_maskNonce ,23);
getRandHashBlock(temp_maskRes ,24);
getRandMessageBlock(maskBlock0 ,25);

   unsigned int statedelta, data_process_modlen;
   long long int i, l = 0;

   /* if |K| > n => return -1  */
   if (10 > OMD_k || OMD_k > OMD_n)
      return -1;

   /* if |N| > n-1 => return -1 */
   if ((12 > OMD_lnonce) || (OMD_lnonce > OMD_n-1))
      return -1;

   /* if |C| < tau => return -1 */
   if ((encrypting == OMD_DECRYPT) && (data_processlen < OMD_tau))
      return -1;




   memset (key_block, 0x00, OMD_n);
   memcpy (key_block, key, OMD_k);

   memset (maskKey_block, 0x00, OMD_n);
   memcpy (maskKey_block, maskKey, OMD_k);





   if (encrypting == OMD_ENCRYPT)
      {
      /* M_1 || M_2 ··· M_{l−1} || M_l = M, where |M_i| = m for 1 ≤ i ≤ l−1
	 and |M_l| ≤ m */
	 /* l = ceil(|M|/m) */
	 l = (data_processlen + (OMD_m-1))/OMD_m;
      }
   else if (encrypting == OMD_DECRYPT)
      {
      /* C_1 || C_2 ··· C_{l−1} || C_l || Tag = \mathbb{C},
	 where |C_i| = m for 1 ≤ i ≤ l−1 and |C_l| ≤ m and |Tag| = \tau*/
      data_processlen = data_processlen - OMD_tau;
      /* l(|C|/m) */
      l = (data_processlen +(OMD_m-1))/OMD_m;

      }

   /* Tag_a computed here to handle a=c overlap */
   /* Tag_a = HASH_k(ad)  */



    messageblock maskedBlock0s;
    xor_block(maskedBlock0s,block0s,maskBlock0);
   secHash(taga, key_block, ad, maskKey_block, maskAd,adlen, maskHash);

   /* CHANGE FROM V1 TO V2 HERE*/
   /* L* = F_K(0^n, <tau>_m) */
   l2b (taures, OMD_tau);
   xor_block(taures,taures,maskTau);




    sec_key_func(lstar,
                 maskedBlock0s,key_block,taures,
                 maskBlock0,maskKey_block,maskTau);




   /* L[0] = 4.L* */
//   sec_double_block()


    sec_double_block(lzero,lstar,maskBlock0);/* 2.L_* */




    sec_double_block(lzero,lzero,maskBlock0);/* 2.(2.L_*) */

   // printf("2lzero: \n");
    //for(i = 0; i <  sizeof(lzero); i++)
       // printf("%u ", lzero[i] ^ maskLzero[i]);
   // printf("\n");


   /* pad nonce */
  memset (nonce_block, 0x00, OMD_n);
   memset (maskNonce, 0x00, OMD_n);

    if (OMD_lnonce < OMD_n){


  memcpy (nonce_block, temp_maskNonce, OMD_n);
   memcpy (maskNonce, temp_maskNonce, OMD_n);
   // Avoid to have part of the masked and nonce mask that are deterministic
    }

   memcpy (nonce_block, nonce, OMD_lnonce);

   memcpy (maskNonce, masknonce, OMD_lnonce);

   nonce_block[OMD_lnonce] = 0x80 ^ maskNonce[OMD_lnonce]; //TOSO check this part may be source of error


   /* \delta{N,0,0} = F_K(N || 10^{n-1-|N|}, 0^m  */






   sec_key_func(delta,
                nonce_block, key_block,maskedBlock0s,
                maskNonce,maskKey_block,maskBlock0
                );
 xor_block(delta,delta, maskDelta);
 xor_block(delta,delta,maskNonce); // Assign an unique mask to delta



   /* H = 0^n */
   memset (h, 0x00, OMD_n );
   xor_block(h,h,maskH); // Assign an unique mask to H

   /* \delta{N,1,0} = \delta{N,0,0} ^ L[ntz(1)]  */
//increment_masking_message (delta, delta, lzero, 1);

    sec_increment_masking_message(delta,
                                 delta,lzero,
                                maskDelta,maskBlock0
                                 ,1);

   /* H = F_K(H ^ \delta_{N, 1, 0}, <tau>_m)  */
   sec_xor_block (h, h, delta,maskH,maskDelta); //TODO ?? not need for sec ?
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



    sec_key_func(h,
                 h, key_block, taures,
                 maskH,maskKey_block,maskTau);



   /* for i = 1 to l-1 do  */
   /************************/
   for (i = 0; i < l-1; i++)
      {
	 /* C_i = H ^ M_i */
	 /* M_i = H ^ C_i */
	 memcpy(res,&data_process[i*OMD_m],OMD_m);
     memcpy(maskRes,&maskData_process[i*OMD_m],OMD_m);


	 sec_xor_block(res2,res,h,maskRes,maskH);
	 hashblock unmaskedRes ="";
     xor_block(unmaskedRes,res2,maskRes);

	 memcpy(&data[i*OMD_m],unmaskedRes,OMD_m);


	 /* \delta_{N, i+1, 0} = \delta{N, i, 0} ^ L[ntz(i+1)]  */
     sec_increment_masking_message(delta,

                                   delta, lzero,

                                   maskDelta, maskBlock0,
                                   i+2);

	 /* H = F_K(H ^ \delta{N, i, 0}, M_i) */


	 sec_xor_block(xor_res,h,delta, maskH, maskDelta); 




	 memcpy(maskTage,maskNonce,OMD_n);

	 if (encrypting == OMD_ENCRYPT) {
	    /* res  = M_i */
	    sec_key_func(h,

              xor_res,key_block,res,
              maskH,maskKey_block,maskRes
              );

	 }
	 else if (encrypting == OMD_DECRYPT){
	    /* res2 = M_i */
	    sec_key_func(h,
                  xor_res,key_block,res2,
                  maskH,maskKey_block,maskRes
                  );
	 }
      }

   /************************/
   /******** endfor ********/


   /* |M|>0 */
   if (data_processlen!=0)
      {
	 /* C_l = H ^ M_l */
	 /* M_l = H ^ C_l *//* |M_l| = m then */
	 data_process_modlen = data_processlen%OMD_m;
	 hashblock maskRes;



  memcpy (res, temp_maskRes, OMD_m);
   memcpy (maskRes, temp_maskRes, OMD_m);


	 memcpy(res, &data_process[(l-1)*OMD_m], (data_process_modlen==0
						  ? OMD_m
						  : data_process_modlen));
    memcpy(maskRes, &maskData_process[(l-1)*OMD_m], (data_process_modlen==0
						  ? OMD_m
						  : data_process_modlen));
	// xor_block(res2, h, res);
	sec_xor_block(res2,res,h,maskRes,maskH);


    hashblock partialres = "";
    xor_block(partialres,res2,maskRes);



	 memcpy(&data[(l-1)*OMD_m], partialres, (data_process_modlen==0
					   ? OMD_m : data_process_modlen));

      /* if |M_\ell|=m */
      if (data_process_modlen == 0)
         statedelta = 1;
      /* else if |M_\ell|<m*/
      else
         statedelta = 2;

      /* \delta{N, l, 1} = \delta{N, l, 0} ^ (2 or 3)*L_* */

      sec_final_masking_message (delta,
                                 delta, lstar,
                                 maskDelta , maskBlock0 ,
                                  statedelta);


      /* Tag_e = F_K(H ^ \delta{N, l, 1}, M_l)  */


      sec_xor_block(h, h, delta,maskH,maskDelta);


      if (encrypting == OMD_ENCRYPT)
	 {
	    /* if |M_\ell|<m, we pad*/
	    if (statedelta==2) {

            res[data_process_modlen]=0x80 ^  maskRes[data_process_modlen];
	    }
              /* res  = M_i */


          sec_key_func (tage,
                        h, key_block, res,
                        maskH, maskKey_block, maskRes);


	 }
      else if (encrypting == OMD_DECRYPT)
	 {


	    if(statedelta==2)
	       {
		  /* if |M_\ell|<m, we pad*/
		  		  //unsecure: res2[data_process_modlen]=0x80;
		 // unsecure(&res2[data_process_modlen+1], 0x00, OMD_m - data_process_modlen - 1);
		  res2[data_process_modlen]=0x80 ^ maskRes[data_process_modlen];



        //maskRes[data_process_modlen]=0x00;
        memcpy(&res2[data_process_modlen+1],&maskRes[data_process_modlen+1],OMD_m - data_process_modlen - 1 );




	       }
        sec_key_func(tage,
                     h , key_block,res2,
                     maskH, maskKey_block,maskRes);
	 }

      }
   /* |M| = 0 => tage = H */
   else
      {
	 memcpy(tage,h,OMD_n);
	 memcpy(maskTage , maskH,OMD_n);
      }


   /* Tag = (Tag_e ^ Tag_a)[n-1 ... n- tau]  */




   sec_xor_block(tag, taga, tage, maskHash,maskH);

   /*ENCRYPT => output tag and return 0*/
   if (encrypting == OMD_ENCRYPT)
      {
        hashblock testout = "";

        xor_block(testout,tag,maskHash);


	 memcpy (&data[data_processlen], testout, OMD_tau);


	 return 0;
      }

   /* or check tag */
   memcpy(tag_prime, &data_process[data_processlen], OMD_tau);

      memcpy(maskTag_prime, &maskData_process[data_processlen], OMD_tau);
    hashblock unmaskedtag ="";
    hashblock unmaskedtagprime = "";

    xor_block(unmaskedtagprime,maskTag_prime,tag_prime );
     xor_block(unmaskedtag, tag,maskHash);


   if (memcmp (unmaskedtag,unmaskedtagprime,OMD_tau) == 0)
      {
	printf("decryption ok");
	 return 0;
      }

   return -1;
}


