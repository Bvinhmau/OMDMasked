/** Implementation of sha256 compression function, originally from openssl  */

/**The original file was modified so that it implements
 * only the compression functions. Below follows the original copyright
 * notice.
*/
/** ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved
 * according to the OpenSSL license [found in ../../LICENSE].
 * ====================================================================
 */

#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#define	DATA_ORDER_IS_BIG_ENDIAN
#include "md32_common.h"
#include "RNGmacro.h"





/** sha256 round constants*/
static const uint32_t K256[64] = {
	0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
	0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
	0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
	0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
	0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
	0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
	0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
	0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
	0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
	0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
	0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
	0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
	0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
	0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
	0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
	0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL };

// /!\ Random numbers and temp value declarations for the macros, don't use variable with temp_... name outside macros/functions.
// Below, all the "temporary mask" used in functions
// (temp_rand_rot1) (temp_rand_rot2)(temp_rand_Ch)(temp_rand_Maj1)(temp_rand_Maj2) (temp_BoolAr_rand)
#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// Secure Random hardcoded , All values related to size Hardcoded
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



//     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#define SecRotate(z,xm,r,u,j)\
({\
((z) =  (ROTATE((xm),j)) );\
((z) = ((u) ^(z)));\
((z) = ((z) ^ (ROTATE((r),j)) ));\
})




//return ch(x,y,z)^t
#define SecCh(z, xm,ym,zm,r,s,t,u)\
({\
	uint32_t (temp_rand_Ch) = 2;\
	uint32_t (temp_maj1)  = 0;\
	uint32_t (temp_maj2) = 0;\
	(SecAnd(temp_maj1,xm,ym,r,s,u));\
	(SecAnd(temp_maj2,~xm,zm,r,t,temp_rand_Ch));\
	(SecXor(z,temp_maj1,temp_maj2,u,temp_rand_Ch));\
})
#define SecMaj(z,xm,ym,zm,r,s,t,u)\
({\
	uint32_t (temp_rand_Maj1) = 150;\
	uint32_t (temp_rand_Maj2) = 213;\
	uint32_t (temp_Maj1) = 0;\
	uint32_t (temp_Maj2) = 0;\
        uint32_t (temp_Maj3) = 0;\
	(SecAnd(temp_Maj1,xm,ym,r,s,u));\
	(SecAnd(temp_Maj2,xm,zm,r,t,temp_rand_Maj1));\
	(SecAnd(temp_Maj3 ,ym,zm,s,t,temp_rand_Maj2));\
	 SecXor(z,temp_Maj1,temp_Maj2,u,temp_rand_Maj1);\
	SecXor(z,z,temp_Maj3,u,temp_rand_Maj2);\
})\

#define SecAdd(z,xm,ym,r,s)\
({\
	z = xm + s;\
	z = z + ym;\
})\
// Conversion function and adder
#define GoudinSub(xm,r) (((xm) ^ (r) ) - (r))


/** sha256 round functions*/
#define Sigma0(x)	(ROTATE((x),30) ^ ROTATE((x),19) ^ ROTATE((x),10))
#define Sigma1(x)	(ROTATE((x),26) ^ ROTATE((x),21) ^ ROTATE((x),7))
#define sigma0(x)	(ROTATE((x),25) ^ ROTATE((x),14) ^ ((x)>>3))
#define sigma1(x)	(ROTATE((x),15) ^ ROTATE((x),13) ^ ((x)>>10))

#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

inline  uint32_t BooleanToArithmetic(uint32_t xm,uint32_t r)
{
	uint32_t (temp_BoolAr_rand) = (14873129);
generateRand(temp_BoolAr_rand,0);
	uint32_t (temp_BoolAr) = temp_BoolAr_rand ^ r;
        uint32_t  A = GoudinSub(xm,temp_BoolAr_rand) ^ GoudinSub(xm,0);
        A = A ^GoudinSub(xm,temp_BoolAr);
        return A;
}
inline  uint32_t ArithmeticToBoolean(uint32_t A2,uint32_t r2)
{
	uint32_t N = 5 ;
	uint32_t (temp_s) ;
	uint32_t (temp_t) ;
	uint32_t (temp_u) ;
generateRand(temp_s,1);
generateRand(temp_t,2);
generateRand(temp_u,3);
	uint32_t shift = 1;
	uint32_t H =0;
	uint32_t U = 0;

	uint32_t P = A2 ^ temp_s;

	P = P^r2;

	uint32_t G = temp_s ^ ( ( A2 ^ temp_t) & r2 );

	G = G ^ (temp_t & r2);
uint32_t P2 = 0;
uint32_t G2 = 0;
	int i=0;
	for ( i=0;i<N-1;i++) { \

		// Same convention than usual (outputvariable,maskedval1,...,maskedvaluen,mask1,...,maskn,[outputmask],[otherneededvariable])
                SecShift( H, G ,   temp_s ,         temp_t ,shift);
		SecAnd(   U, P, H, temp_s,  temp_t ,temp_u);

		G2 = G;
		SecXor(   G, G2, U, temp_s,          temp_u );
		SecShift( H, P,    temp_s,          temp_t, shift);
		P2 = P;
		SecAnd(   P, P2, H, temp_s,  temp_t, temp_u);

		P = P ^temp_s ;

		P = P ^temp_u ;
		shift =(shift<<1);
	}\


	SecShift(H,G,temp_s,temp_t,shift);
	SecAnd(U,P,H,temp_s,temp_t,temp_u);
	SecXor(G,G,U,temp_s,temp_u);
        uint32_t xm =  A2 ^ (G<<1);
	xm = xm ^ (temp_s << 1);
       return xm;
}


// WARNING: As variable name A,B,C,... and Ti (for all i = 1,2,3...) may be used is the macro, using them below will break the code.


inline  uint32_t SecSigma0(uint32_t xm,uint32_t r,uint32_t u)
{
	uint32_t z = 0;
	uint32_t (t6) ;
	uint32_t (t7) ;
generateRand(t6,4);
generateRand(t7,5);
	uint32_t (C) = 0;
	uint32_t (D) = 0;
	uint32_t temp_C = 0;
	(SecRotate(temp_C,xm,r,u,30));
	(SecRotate(D,xm,r,t6,19));
	(SecXor(C,temp_C,D,u,t6));
	(SecRotate(D,xm,r,t7,10));
	(SecXor(z,C,D,u,t7));
	return z;
}

inline  uint32_t SecSigma1(uint32_t xm,uint32_t r,uint32_t u)\
{
	uint32_t z = 0;
	uint32_t (t6) ;
	uint32_t (t7) ;
generateRand(t6,6);
generateRand(t7,7);
	uint32_t (E) = 0;
	uint32_t (F) = 0;
	uint32_t (temp_c) = 0;
	SecRotate(temp_c,xm,r,u,26);
        (SecRotate(F,xm,r,t6,21));
	(SecXor(E,temp_c,F,u,t6));
	(SecRotate(F,xm,r,t7,7));
	(SecXor(z,E,F,u,t7));
	return z;
}
// #define Sigma1(x)	(ROTATE((x),26) ^ ROTATE((x),21) ^ ROTATE((x),7))

inline  uint32_t Secsigma0(uint32_t xm,uint32_t r,uint32_t u)
{
	uint32_t z = 0;
	uint32_t (t10) ;
	uint32_t (t11) ;
	uint32_t K = 0;
	uint32_t L = 0;
	uint32_t temp_K = 0;
generateRand(t10,8);
generateRand(t11,9);
	SecRotate(temp_K,xm,r,u,25);
	SecRotate(L,xm,r,t10,14);
	SecXor(K,temp_K,L,u,t10);
	SecShiftR(L,xm,r,t11,3);
	SecXor(z,K,L,u,t11);
	return z ;
}

inline  uint32_t Secsigma1(uint32_t xm,uint32_t r,uint32_t u)
{

	uint32_t z = 0;
	uint32_t (t10) ;
	uint32_t (t11) ;

	uint32_t K = 0;
	uint32_t L = 0;
generateRand(t10,10);
generateRand(t11,11);
	uint32_t temp_K = 0;
	SecRotate(temp_K,xm,r,u,15);
	SecRotate(L,xm,r,t10,13);
	SecXor(K,temp_K,L,u,t10);
	SecShiftR(L,xm,r,t11,10);
	SecXor(z,K,L,u,t11);
	//printf("Z %u \n " , z ^u);
	return z ;
}


void Sec_sha256_comp (hashblock res,
                      const hashblock hash, const void *in ,
                       const hashblock hashmask , const void *inmask)
	{



	uint32_t a,b,c,d,e,f,g,h,s0,s1,T1,T2;
	uint32_t    H[8];
	uint32_t	X[16],l,m,om;
	int i;
	uint32_t 	Mx[16];
	uint32_t Ma,Mb,Mc,Md,Me,Mf,Mg,Mh; // 8 random number generation
	uint32_t MT2 , MS1, MCh,MMaj , Mss0 , Mss1; // 6 random number generation
	uint32_t tempout;
    uint32_t oriM[16];
    uint32_t xm[16];

// Some of them will be generated randomly (ie Mx[i]...), some just need a fixed value at the beginning of the computation (ie Ma,Mb...)

 MT2 = 324255;  MS1 = 9387323; MCh = 2328284; MMaj = 18273242;
Mss0 = 1635134; Mss1 = 7264274;


generateRand(MT2,12);
generateRand(MS1,13);
generateRand(MCh,14);
generateRand(MMaj,15);
generateRand(Mss0,16);
generateRand(Mss1,17);
generateRand(tempout,37);

	const unsigned char *data=in;
	const unsigned char *datamask=inmask;
	for (i=0;i<SHA256_DIGEST_LENGTH/4;i++){
    HOST_c2l(hashmask,oriM[i]);


        HOST_c2l(hash, H[i]);

	}

// Initialize the value for the SHA register and their masks
a = H[0];	b = H[1];	c = H[2];	d = H[3];
e = H[4];	f = H[5];	g = H[6];	h = H[7];
    Ma = oriM[0];
    Mb = oriM[1];
    Mc = oriM[2];
    Md = oriM[3];
    Me = oriM[4];
    Mf = oriM[5];
    Mg = oriM[6];
    Mh = oriM[7];





	for (i=0;i<16;i++)
		{

		HOST_c2l(data,l);  xm[i] = l ;
		HOST_c2l(datamask,m);  Mx[i] = m ;

		// Computing T1, at every step of the computation, it mask is Xm[i]
		// First, we generate all the intermediate result with Boolean Masking
		uint32_t temp_1 = 0;
                uint32_t temp_2 = 0;
                uint32_t ch = 0;

		SecCh( ch, e,f,g,Me,Mf,Mg,MCh);
		uint32_t sig1 = SecSigma1(e,Me,MS1);

 		// Then convert every used result in Arithmetic domain
		ch  = BooleanToArithmetic(ch,MCh);
		sig1 = BooleanToArithmetic(sig1,MS1);
		uint32_t arXm = BooleanToArithmetic(xm[i],Mx[i]);
		uint32_t arh = BooleanToArithmetic(h,Mh);

 		SecAdd(temp_1, arXm,   arh, Mx[i] , Mh);
 		SecAdd(temp_2, temp_1, sig1,Mx[i] , MS1);
		SecAdd(temp_1, temp_2, ch,  Mx[i], MCh);
		T1 = (temp_1 + K256[i]); // The mask of T1 is now Mx(i)


		// Computing T2, at every step of the computation, it mask is MT2
		// First, we generate all the intermediate result with Boolean Masking
		uint32_t sig0 = SecSigma0(a,Ma,MT2);
                uint32_t maj = 0;
		SecMaj(maj,a,b,c,Ma,Mb,Mc,MMaj);
 		// Then convert every used result in Arithmetic domain
		sig0 = BooleanToArithmetic(sig0,MT2);
		maj = BooleanToArithmetic(maj,MMaj);
		SecAdd(T2,sig0,maj,MT2,MMaj);


	        // This part switch the register and their mask values
		h = g;
		Mh = Mg;
		g = f;
		Mg = Mf;
		f = e;
		Mf = Me;


		uint32_t ard = BooleanToArithmetic(d,Md);
		SecAdd(e,ard,T1,Md,Mx[i]);

		e = ArithmeticToBoolean(e,Md);
		Me = Md;


		d = c;
		Md = Mc;
		c = b;
		Mc = Mb;
		b = a;
		Mb = Ma;
		SecAdd(a,T1,T2,Mx[i],MT2);
		a = ArithmeticToBoolean(a,Mx[i]);
		Ma = Mx[i];

		}

uint32_t xm1, xm0;
	for (;i<64;i++)
		{
		xm0 = xm[(i+1)&0x0f] ;uint32_t m0 =Mx[(i+1)&0x0f];	s0 = Secsigma0(xm0,m0,Mss0);

		xm1 = xm[(i+14)&0x0f];uint32_t m1 =Mx[(i+14)&0x0f];	s1 = Secsigma1(xm1,m1,Mss1);

	 	// Original Implementations
		//T1 = X[i&0xf] += s0 + s1 + X[(i+9)&0xf];
		//T1 += h + Sigma1(e) + Ch(e,f,g) + K256[i];
		s0 = BooleanToArithmetic(s0,Mss0);
		s1 = BooleanToArithmetic(s1,Mss1);
		uint32_t arX1 = BooleanToArithmetic(xm[i&0xf],Mx[i&0xf]);
		uint32_t arX2 = BooleanToArithmetic(xm[(i+9)&0xf],Mx[(i+9)&0xf]);

		uint32_t temp1 = 0 ;
		uint32_t temp2 = 0;
		uint32_t temp_T1 = 0;

		SecAdd(temp1, arX1 , s0, Mx[i&0xf],Mss0);
		SecAdd(temp2, arX2 , s1, Mx[(i+9)&0xf],Mss1);
		SecAdd(temp_T1,temp1,temp2,Mx[i&0xf],Mx[(i+9)&0xf]);

		//Updating the Message Schedule
		xm[i&0xf] = ArithmeticToBoolean(temp_T1,Mx[i&0xf]);

		//T1 = X[i&0xf] += s0 + s1 + X[(i+9)&0xf];
                uint32_t ch = 0;
		SecCh( ch, e,f,g,Me,Mf,Mg,MCh);
		uint32_t sig1 = SecSigma1(e,Me,MS1);

 		// Then convert every used result in Arithmetic domain
		ch  = BooleanToArithmetic(ch,MCh);
		sig1 = BooleanToArithmetic(sig1,MS1);
		uint32_t arXm = BooleanToArithmetic(xm[i],Mx[i]);
		uint32_t arh = BooleanToArithmetic(h,Mh);

 		SecAdd(temp1, temp_T1,   arh, Mx[i&0xf] , Mh);
 		SecAdd(temp2, temp1, sig1,Mx[i&0xf] , MS1);
		SecAdd(temp1, temp2, ch,  Mx[i&0xf], MCh);

		T1 = (temp1 + K256[i]);

		// Computing T2, at every step of the computation, it mask is MT2
		// First, we generate all the intermediate result with Boolean Masking
		uint32_t sig0 = SecSigma0(a,Ma,MT2);
                uint32_t maj = 0;
		SecMaj(maj,a,b,c,Ma,Mb,Mc,MMaj);
 		// Then convert every used result in Arithmetic domain
		sig0 = BooleanToArithmetic(sig0,MT2);
		maj = BooleanToArithmetic(maj,MMaj);
		T2 = 0;
		SecAdd(T2,sig0,maj,MT2,MMaj);

		h = g;
		Mh = Mg;
		g = f;
		Mg = Mf;
		f = e;
		Mf = Me;


		uint32_t ard = BooleanToArithmetic(d,Md);
		SecAdd(e,ard,T1,Md,Mx[i&0xf]);
		e = ArithmeticToBoolean(e,Md);
		Me = Md;


		d = c;
		Md = Mc;
		c = b;
		Mc = Mb;
		b = a;
		Mb = Ma;

		SecAdd(a,T1,T2,Mx[i&0xf],MT2);
		a = ArithmeticToBoolean(a,Mx[i&0xf]);
		Ma = Mx[i&0xf];




		}
uint32_t regMask[8];
regMask[0] = Ma; regMask[1] = Mb; regMask[2] = Mc; regMask[3] = Md;
regMask[4] = Me; regMask[5] = Mf; regMask[6] = Mg; regMask[7] = Mh;

uint32_t reg[8];
reg[0] = a; reg[1] = b; reg[2] = c; reg[3] = d;
reg[4] = e; reg[5] = f; reg[6] = g; reg[7] = h;


for (i = 0; i < 8 ; i++ ) {
    reg[i]= reg[i] ^ tempout;
    reg[i]= reg[i] ^ regMask[i]; // mask refreshing has ti be used tç avoid unmasking in the last XOR

    uint32_t arH = BooleanToArithmetic(H[i], oriM[i]);
    uint32_t arIncr =  BooleanToArithmetic(reg[i], tempout);
    uint32_t z = 0;
    SecAdd(z,arH,arIncr,oriM[i],tempout);
    z = ArithmeticToBoolean(z,oriM[i]);

    HOST_l2c(z, res);

}


}


/*****************************************
 *       sha256 compression function     *
 *                                       *
 *   H   points to chaining input        *
 *   in  points to the message input     *
 *                                       *
 *****************************************/
void sha256_comp (hashblock res, const hashblock hash, const void *in)
	{
	uint32_t a,b,c,d,e,f,g,h,s0,s1,T1,T2;
	uint32_t    H[8];
	uint32_t	X[16],l;
	int i;
	const unsigned char *data=in;

	for (i = 0; i < SHA256_DIGEST_LENGTH/4; i++) {
	   HOST_c2l(hash, H[i]);
	}

	a = H[0];	b = H[1];	c = H[2];	d = H[3];
	e = H[4];	f = H[5];	g = H[6];	h = H[7];


	for (i=0;i<16;i++)
		{
		HOST_c2l(data,l); T1 = X[i] = l;
		T1 += h + Sigma1(e) + Ch(e,f,g) + K256[i];
		T2 = Sigma0(a) + Maj(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;	c = b;	b = a;	a = T1 + T2;
		}

	for (;i<64;i++)
		{
		s0 = X[(i+1)&0x0f];	s0 = sigma0(s0);
		s1 = X[(i+14)&0x0f];	s1 = sigma1(s1);

		T1 = X[i&0xf] += s0 + s1 + X[(i+9)&0xf];
		T1 += h + Sigma1(e) + Ch(e,f,g) + K256[i];
		T2 = Sigma0(a) + Maj(a,b,c);
		h = g;	g = f;	f = e;	e = d + T1;
		d = c;	c = b;	b = a;	a = T1 + T2;
		}

    // Boolean to Ar
	H[0] += a;	H[1] += b;	H[2] += c;	H[3] += d;
	H[4] += e;	H[5] += f;	H[6] += g;	H[7] += h;

	for (i = 0; i < SHA256_DIGEST_LENGTH/4; i++) {

	   HOST_l2c(H[i], res);
	}
}


