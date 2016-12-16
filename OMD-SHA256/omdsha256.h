/**
 * The implementation of the omdsha256 mode
 *
 * Notes to implementation:
 *
 * 1) OMD parameters
 *   In the specification of OMD, following parameters are defined:
 *       - key length k
 *       - nonce length |N|
 *       - tag length tau
 *       - length of the message block m
 *       - length of the chaining block n
 *
 *   In the specification, all of these parameters indicate lengths of
 *   corresponding components of OMD in *bits*.
 *   The CAESAR api is Byte-oriented, i.e. all the inputs and ouptuts of
 *   encryption and decryption algorithms have bit-length, that is always
 *   a multiple of 8.
 *   Therefore, in this implementation of OMD, the parameters mentioned
 *   above indicate length of corresponding components of OMD in *Bytes*.
 *   Comming hand to hand with this, this implementation only handles
 *   inputs with bitlength that is always a multiple of 8!
 *
 *   Sticking with bit-lengths instead of Byte-lengths would add sensless
 *   computational overhead (in software) and worsen readability of code.
 *
 * 2) Treatment of bit-indexing
 *   In the specification of OMD, the output and input blocks of
 *   compression functions
 *   are treated as atomic, e.g. the chaining block H in sha256
 *   compression function
 *   is considered to be a block of 256 bits. However, when implementing
 *   the scheme,
 *   these big blocks have to be represented by arrays of smaller units
 *   (e.g. Bytes).
 *   In this implementation, we treat the representations of such arrays
 *   in following
 *   manner:
 * <center>
 * <table>
 *  <tr>
 *   <th>Bits in block</th>
 *   <td>255</td>
 *   <td>254</td>
 *   <td>253</td>
 *   <td>252</td>
 *   <td>251</td>
 *   <td>250</td>
 *   <td>249</td>
 *   <td>248</td>
 *   <td>247</td>
 *   <td>...</td>
 *   <td>7</td>
 *   <td>6</td>
 *   <td>5</td>
 *   <td>4</td>
 *   <td>3</td>
 *   <td>2</td>
 *   <td>1</td>
 *   <td>0</td>
 *  </tr>
 *  <tr>
 *   <th>Bits in bytes</th>
 *   <td>7</td>
 *   <td>6</td>
 *   <td>5</td>
 *   <td>4</td>
 *   <td>3</td>
 *   <td>2</td>
 *   <td>1</td>
 *   <td>0</td>
 *   <td colspan=2>7 ...</td>
 *   <td>7</td>
 *   <td>6</td>
 *   <td>5</td>
 *   <td>4</td>
 *   <td>3</td>
 *   <td>2</td>
 *   <td>1</td>
 *   <td>0</td>
 *  </tr>
 *  <tr>
 *   <th> Byte index</th>
 *   <td colspan=8><center>0</center></td>
 *   <td colspan=2><center>1...</center></td>
 *   <td colspan=8><center>31</center></td>
 *  </tr>
 * </table>
 * </center>
 *
 * 3) Computing the L values
 *   The specification of OMD states, that the values L*, L[i] i=0,1..
 *   can either be
 *   precomputed and stored, or computed on the fly. In this implementation,
 *   the L values are *computed on the fly*.
 *
 * @file omdsha256.h
 * @author Simon Cogliani <simon.cogliani@gmail.com>
 * @author Damian Vizar <damian.vizar@epfl.ch>
 */
#ifndef __SHA256OMD_H__
#define __SHA256OMD_H__

#include "sha256.h"
#include "omd_api.h"





#define OMD_n SHA256_DIGEST_LENGTH /**< Byte-length of the chaining block */
#define OMD_m SHA256_DIGEST_LENGTH /**< Byte-length of the message block  */
#define OMD_COMP sha256_comp       /**< Macro for compression function    */
#define SEC_OMD_COMP Sec_sha256_comp
#define OMD_tau CRYPTO_ABYTES           /**< Byte-length of the tag   */
#define OMD_k CRYPTO_KEYBYTES           /**< Byte-length of the key   */
#define OMD_lnonce CRYPTO_NPUBBYTES     /**< Byte-length of the nonce */

/**
 * Constant zero message block - used multiple times
 */
static const messageblock
block0s =
   {
      0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0
   };

/**
 * Flags to identify sort of cryptographic process
 */
enum mode
{
   OMD_ENCRYPT, /**< Encrypting process */
   OMD_DECRYPT  /**< Decrypting process */
};

/**
 * The XOR operation
 * @param res The result of the computation
 * @param in1 The left operand
 * @param in2 The right operand
 */
void
xor_block (hashblock res, const hashblock in1, const hashblock in2);

/**
 * Computes in \f$GF(2^{256})[X]/(X^{256} + X^{10} + X^5 + X^2 + 1)\f$ a.X
 * where a is in the finite field
 * @param res The result of the computation
 * @param in a polynomial in \f$GF(2^{256})[X]/(X^{256} + X^{10} + X^5 + X^2
 *        + 1)\f$
 */
void
double_block (hashblock res, const hashblock in);

/**
 * Computes in \f$GF(2^{256})[X]/(X^{256} + X^{10} + X^5 + X^2 + 1)\f$
 * a.(X+1) where a is in the finite field
 * @param res The result of the computation
 * @param in a polynomial in \f$GF(2^{256})[X]/(X^{256} + X^{10} + X^5 + X^2
 *        + 1)\f$
 */
void
triple_block (hashblock res, const hashblock in);

/**
 * Converts a byte-length value to bit string representation of corresponding bit-length
 * @param bit_string The bit string representation
 * @param value Value in bytes
 */
void
l2b (hashblock bit_string, int value);

/**
 * We define \f$F_{K}(H, M) = F(H, K || M)\f$
 * @param res The output
 * @param hash The chaining input
 * @param key The key
 * @param message The message input
 */

void
key_func (hashblock res, const hashblock hash, const hashblock key,
	  const hashblock message);

/**
 * Computes the \f$L[i]\f$
 * @param l The result of the computation
 * @param lzero The value of \f$L[0] = 4.L^*\f$
 * @param i The index \f$i\f$
 */
void
calc_L_i (hashblock l, const hashblock lzero, unsigned int i);

/**
 * Computes the number of trailing zeros
 * @param i The input whose ntz we want
 */
int
ntz (int i);

/**
 * Masking sequence for processing the message, j=0
 * @param delta_n New mask \f$\Delta_{N,i,0}\f$
 * @param delta_o Previous mask \f$\Delta_{N,i-1,0}\f$
 * @param lzero \f$L[0]\f$
 * @param i The ith \f$L\f$
 * @pre \f$i \geq 1\f$
 */
void
increment_masking_message (hashblock delta_n, const hashblock delta_o,
			   const hashblock lzero, int i) ;

/**
 * Masking sequence for processing the message - last mask.
 * @param delta_n New mask \f$\Delta_{N,i,j}\f$
 * @param delta_o Previous mask \f$\Delta_{N,i,0}\f$
 * @param lstar \f$L^*\f$
 * @param j The ith \f$L\f$
 */
void
final_masking_message (hashblock delta_n, const hashblock delta_o,
		       const hashblock lstar, int j);

/**
 * Masking sequence for processing the associated data, j=0
 * @param delta_n New mask \f$\bar{\Delta}_{i,0}\f$
 * @param delta_o Previous mask \f$\bar{\Delta}_{i-1,0}\f$
 * @param lzero \f$L[0]\f$
 * @param i The ith \f$L\f$
 */
void
increment_masking_associated_data (hashblock delta_n, const hashblock delta_o,
				   const hashblock lzero, int i) ;

/**
 * Masking sequence for processing the associated data, j=1
 * @param delta_n New mask \f$\bar{\Delta}_{i,1}\f$
 * @param delta_o Previous mask \f$\bar{\Delta}_{i,0}\f$
 * @param lstar \f$L^*\f$
 */
void
final_masking_associated_data (hashblock delta_n, const hashblock delta_o,
			       const hashblock lstar);



/**
 * Hash function for processing associated data
 * @param taga The output tag, 
 * @param key The secret key
 * @param ad A pointer to associated data
 * @param adlen Length of associated data in Bytes
 */
void
hash (hashblock taga, const hashblock key, const unsigned char *ad,
      unsigned long long int adlen);



//PPOOOOIIII
/**
 * The XOR operation, in it masked version
 * @param res The result of the computation masked with mask1
 * @param in1 The left operand
 * @param in2 The right operand
 * @param mask1 The mask of in1
 * @param mask2 The mask of in2
 */
void
sec_xor_block (hashblock res, const hashblock in1, const hashblock in2, const hashblock mask1, const hashblock mask2);

/**
 * Computes in \f$GF(2^{256})[X]/(X^{256} + X^{10} + X^5 + X^2 + 1)\f$ a.X , in it masked secure version
 * where a is in the finite field
 * @param res The result of the computation masked with mask
 * @param in a polynomial in \f$GF(2^{256})[X]/(X^{256} + X^{10} + X^5 + X^2
 *        + 1)\f$ in it masked version
 * @param mask the mask of in
 */
void
sec_double_block (hashblock res, const hashblock in, const hashblock mask);

/**
 * Computes in \f$GF(2^{256})[X]/(X^{256} + X^{10} + X^5 + X^2 + 1)\f$ in it masked secure version
 * a.(X+1) where a is in the finite field
 * @param res The result of the computation masked with mask
 * @param in a polynomial in \f$GF(2^{256})[X]/(X^{256} + X^{10} + X^5 + X^2
 *        + 1)\f$  in it masked version
 * @param mask the mask of in
 */
void
sec_triple_block (hashblock res, const hashblock in, const hashblock mask);

/**
 * Computes the \f$L[i]\f$ , in it version secured with maskin
 * @param l The result of the computation masked with masklzero
 * @param lzero The value of \f$L[0] = 4.L^*\f$
*  @param masklzero the mask of \f$L[0] = 4.L^*\f$
 * @param i The index \f$i\f$
 */

void sec_calc_L_i (hashblock l, const hashblock lzero, const hashblock masklzero, unsigned int i);


/**
 * Masking sequence for processing the message - last mask, in it version secured with masking
 * @param delta_n New mask \f$\Delta_{N,i,j}\f$ masked with maskDelta_o
 * @param delta_o Previous mask \f$\Delta_{N,i,0}\f$ in it masked version
 * @param lstar \f$L^*\f$ in it masked version
* @param maskDelta_o mask of \f$\Delta_{N,i,0}\f$
* @param maskLstar mask of \f$L^*\f$
 * @param j The ith \f$L\f$
 */
void
sec_final_masking_message (hashblock delta_n,
                           const hashblock delta_o,const hashblock lstar,
                           const hashblock maskDelta_o , const  hashblock maskLstar ,
                           int j);


/**
 * Masking sequence for processing the associated data, j=0 in it version secured with masking
 * @param delta_n New mask \f$\bar{\Delta}_{i,0}\f$ masked with maskDelta_o
 * @param delta_o Previous mask \f$\bar{\Delta}_{i-1,0}\f$ in it masked version
 * @param lzero \f$L[0]\f$, in it masked version

 * @param maskDelta_o the mask of \f$\bar{\Delta}_{i-1,0}\f$
* @param maskLzero the mask of \f$L[0]\f$
 * @param i The ith \f$L\f$ 
*/
void sec_increment_masking_associated_data (hashblock delta_n,
                   const hashblock delta_o,const hashblock lzero,
				   const hashblock maskDelta_o, const hashblock maskLzero
				   , int i);


/**
 * Masking sequence for processing the associated data, j=0 , in it version secured with masking.
 * @param delta_n New mask \f$\bar{\Delta}_{i,0}\f$ masked wih maskDelta_o

 * @param delta_o Previous mask \f$\bar{\Delta}_{i-1,0}\f$ in it masked version
 * @param lzero \f$L[0]\f$ in it masked version
*@param maskDelta_o mask of \f$\bar{\Delta}_{i-1,0}\f$
*@param masklzero mask of \f$L[0]\f$ 

 * @param i The ith \f$L\f$
 */

void sec_increment_masking_message (hashblock delta_n,
		                       const hashblock delta_o,const hashblock lzero,
		                       const hashblock maskdelta_o , const hashblock masklzero, int i);

/**
 * Masking sequence for processing the associated data, j=1, in it in it version secured with masking.
 * @param delta_n New mask \f$\bar{\Delta}_{i,1}\f$ , masked wih maskDelta_o
 * @param delta_o Previous mask \f$\bar{\Delta}_{i,0}\f$ in it masked version
 * @param lstar \f$L^*\f$ in masked version
*@param maskDelta_o mask of \f$\bar{\Delta}_{i,0}\f$
*@param maskLstar mask of \f$L^*\f$ 
 */


void
sec_final_masking_associated_data (hashblock delta_n,
                                   const hashblock delta_o, const hashblock lstar,
                                   const hashblock maskDelta_o, const hashblock maskLstar);

/**
 * We define \f$F_{K',maskK}(H', M', maskH,maskM) = F(H', K' || M', maskH,maskK|| maskM)\f$
 * @param res The output, masked with maskHash
 * @param hash The chaining input, in it masked version
 * @param key The key in it masked version
 * @param message The message input in it masked version
* @param maskHash the mask of the hash 
* @param maskKey the mask of the key
* @param maskMessage the mask of the message

 */



void
sec_key_func (hashblock res, const hashblock hash, const hashblock key,
	  const hashblock message, const hashblock maskHash, const hashblock maskKey, const hashblock maskMessage);



      /**
 * Hash function for processing associated data, in it version secured with masking.
 * @param taga The output tag
 * @param key The secret key, in it masked version
 * @param ad A pointer to associated data, in it masked version

 *@param maskKey The mask of the secret key
 * @param maskAd A pointer to the mask of the associated data
 * @param adlen Length of associated data in Bytes
 @param outputMask the mask of the ouput
 */
void
secHash (hashblock taga, const hashblock key, const unsigned char *ad, const hashblock maskKey, const unsigned char *maskAd,
      unsigned long long int adlen , hashblock outputMask);

/**
 * The SHA-256-OMD encrypt/decrypt function
 * @param data A pointer to output buffer
 * @param key The secret key
 * @param k Key length in Bytes
 * @param data_process A pointer to the data that is to be processed
 *        - the interpretation depends on the encrypting flag
 * @param data_processlen Length of input data in Bytes
 * @param ad A pointer to associated data
 * @param adlen Length of associated data in Bytes
 * @param nonce A pointer to the nonce
 * @param lnonce Nonce length in Bytes
 * @param tau Tag length in Bytes
 * @param encrypting A flag to select encryption/decryption
 */
int
omdsha256_process(unsigned char *data, const unsigned char* key,
		  const unsigned char *data_process,
		  unsigned long long int data_processlen,
		  const unsigned char *ad, unsigned long long int adlen,
		  const unsigned char *nonce,
		  const enum mode encrypting);

/**
 * The SHA-256-OMD encrypt/decrypt function, in it version secured with masking.
 * @param data A pointer to output buffer
 * @param key The  masked version of the secret key
 * @param data_process A pointer to the masked version of thedata that is to be processed
 *        - the interpretation depends on the encrypting flag
 * @param ad A pointer to masked version of the associated data
 * @param nonce A pointer to the nonce

 * @param maskkey The mask of the secret key
 * @param maskData_process A pointer to the mask of the data that is to be processed
 * @param maskad A pointer to mask of associated data
 * @param masknonce A pointer to mask of the nonce

 * @param data_processlen Length of input data in Bytes
 * @param adlen Length of associated data in Bytes

 * @param encrypting A flag to select encryption/decryption
 */

int
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

	const enum mode encrypting);

#endif /* not __SHA256OMD_H__ */
