#ifndef __MPCCYRPTO_H_
#define __MPCCYRPTO_H_

#define OTEXT_USE_GMP
//#define OTEXT_USE_ECC
//#define OTEXT_USE_PRIMEFIELD
#define OTEXT_USE_OPENSSL
//#define USESHA1 //Switch between SHA1 and SHA256

#include "typedefs.h"



#define AES_KEY_BITS			128
#define AES_KEY_BYTES			16
#define AES_BITS				128
#define AES_BYTES				16
#define LOG2_AES_BITS			CEIL_LOG2(AES_BITS)

typedef struct SECURITYLEVELS
{
	int statbits;
	int symbits;
	int ifcbits;
	int eccpfbits;
	int ecckcbits;
} SECLVL;

#include "../util/Miracl/ecn.h"
#include "../util/Miracl/big.h"
#include "../util/Miracl/ec2.h"
#ifdef OTEXT_USE_GMP
#include <gmp.h>
#endif


/* Predefined security levels,
 * ST (SHORTTERM) = 1024/160/163 bit public key, 80 bit private key
 * MT (MEDIUMTERM) = 2048/192/233 bit public key, 96 bit private key
 * LT (LONGTERM) = 3072/256/283 bit public key, 128 bit private key
 * XLT (EXTRA LONGTERM) = 7680/384/409 bit public key, 192 bit private key
 * XXLT (EXTRA EXTRA LONGTERM) = 15360/512/571 bit public key, 256 bit private key
 */

static const SECLVL ST = {40, 80, 1024, 160, 163};
static const SECLVL MT = {40, 96, 2048, 192, 233};
static const SECLVL LT = {40, 128, 3072, 256, 283};
static const SECLVL XLT = {40, 192, 7680, 384, 409};
static const SECLVL XXLT = {40, 256, 15360, 512, 571};
//enum PREDEFSECURITYLEVEL {ST, MT, LT};
//typedef PREDEFSECURITYLEVEL SECLVL;


#define SYMMETRIC_SECURITY_PARAMETER 128 //security parameter for Yao's garbled circuits
#define SSP SYMMETRIC_SECURITY_PARAMETER
#define BYTES_SSP SSP/8
#define NUM_EXECS_NAOR_PINKAS SSP
#define NUM_EXECS_NAOR_PINKAS_BYTES NUM_EXECS_NAOR_PINKAS/8

#define MAXMSGSAMPLE 40

#if SSP == 80
#define USESHA1 //Switch between SHA1 and SHA256
#endif

#ifdef OTEXT_USE_OPENSSL

#include <openssl/evp.h>
#include <openssl/sha.h>


#ifdef USESHA1

#define SHA1_BYTES				20
#define SHA1_BITS				160

typedef SHA_CTX HASH_CTX;
#define MPC_HASH_INIT(sha) SHA1_Init(sha)
#define MPC_HASH_UPDATE(sha, buf, bufsize) SHA1_Update(sha, buf, bufsize)
#define MPC_HASH_FINAL(sha, sha_buf) SHA1_Final(sha_buf, sha)

#else

#define SHA1_BYTES				32
#define SHA1_BITS				256

typedef SHA256_CTX HASH_CTX;
#define MPC_HASH_INIT(sha) SHA256_Init(sha)
#define MPC_HASH_UPDATE(sha, buf, bufsize) SHA256_Update(sha, buf, bufsize)
#define MPC_HASH_FINAL(sha, sha_buf) SHA256_Final(sha_buf, sha)

#endif


const unsigned char ZERO_IV[AES_BYTES]={0};
static int otextaesencdummy;


typedef EVP_CIPHER_CTX AES_KEY_CTX;
#define MPC_AES_KEY_INIT(ctx) EVP_CIPHER_CTX_init(ctx)
#define MPC_AES_KEY_EXPAND(ctx, buf) EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, buf, ZERO_IV)
#define MPC_AES_ENCRYPT(keyctx, outbuf, inbuf) EVP_EncryptUpdate(keyctx, outbuf, &otextaesencdummy, inbuf, AES_BYTES)

#else

#include "aes.h"
#include "sha1.h"


typedef SHA_CTX HASH_CTX;
#define MPC_HASH_INIT(sha) sha1_starts(sha)
#define MPC_HASH_UPDATE(sha, buf, bufsize) sha1_update(sha, buf, bufsize)
#define MPC_HASH_FINAL(sha, sha_buf) sha1_finish(sha, sha_buf)

#define AES_KEY_CTX AES_KEY
#define MPC_AES_KEY_INIT(ctx) //nothingprivate_AES_set_encrypt_key(buf, AES_KEY_BITS, ctx)
#define MPC_AES_KEY_EXPAND(ctx, buf) private_AES_set_encrypt_key(buf, AES_KEY_BITS, ctx)
#define MPC_AES_ENCRYPT(keyctx, outbuf, inbuf) AES_encrypt(inbuf, outbuf, keyctx)


#endif



struct ecc_field_parameters {
	Big* BA;
	Big* BB;
	Big* X;
	Big* Y;
	Big* BP;
	int m;
	int a;
	int b;
	int c;
};
typedef ecc_field_parameters eccfparams;

#ifdef OTEXT_USE_GMP
struct gmp_field_parameters {
	mpz_t p;
	mpz_t g;
	mpz_t q;
	gmp_randstate_t	rnd_state;
};
typedef gmp_field_parameters ifcfparams;
#endif

struct field_parameters {
	/* The field size in bytes */
	int elebytelen;
	int secparam;
	union {
		eccfparams eccparams;
#ifdef OTEXT_USE_GMP
		ifcfparams ifcparams;
#endif
	};

};
typedef field_parameters fparams;



#ifdef OTEXT_USE_GMP
#include "brick.h"
#include "double-exp.h"


typedef mpz_t fieldelement;
typedef mpz_t number;
//typedef class FixedExpPoint brickexp; //in brick.h
#define FieldGetGenerator(mg, mparams) mpz_set((mg), mparams.ifcparams.g)
#define FieldInit(secparam, seed, param) GMPInit(secparam, seed, (&param))
#define FieldCleanup(param) GMPCleanup((&param))
#define BrickInit(br, base, params) (br)->Init((base), params.ifcparams.p, params.secparam)
#define BrickDelete(br)
#define BrickPowerMod(bg, res, x) (bg)->powerMod(res, x)
#define FieldElementInit(fe) mpz_init(fe)
#define FieldElementSet(dst,src) mpz_set(dst, src)
#define FieldElementMul(res, a, b, params) { \
		mpz_mul(res, a, b); \
		mpz_mod(res, res, params.ifcparams.p); \
}
#define FieldElementPow(res, a, b, params)	mpz_powm(res, a, b, params.ifcparams.p)
#define FieldElementDiv(res, a, b, params) { \
		mpz_t DIV_TMP; \
		mpz_init(DIV_TMP); \
		mpz_invert(DIV_TMP, b, params.ifcparams.p); \
		mpz_mul(DIV_TMP, a, DIV_TMP); \
		mpz_mod(res, DIV_TMP, params.ifcparams.p); \
}
#define FieldElementDoublePowMul(res, b1, e1, b2, e2, params) { \
	mpz_t DMPRES1, DMPRES2; \
	mpz_init(DMPRES1); \
	mpz_init(DMPRES2); \
	mpz_powm(DMPRES1, b1, e1, params.ifcparams.p); \
	mpz_powm(DMPRES2, b2, e2, params.ifcparams.p); \
	mpz_mul(res, DMPRES1, DMPRES2); \
	mpz_mod(res, res, params.ifcparams.p); \
}

#define NumberSet(dst,src) mpz_set(dst, src)
#define NumberSetSI(dst,src) mpz_set_si(dst, src)
#define NumberAdd(res, a, b) mpz_add(res, a, b)
#define NumberMul(res, a, b) mpz_mul(res, a, b)

#define ByteToFieldElement(ele, bytelen, buf) mpz_import((*ele), bytelen, 1, sizeof((buf)[0]), 0, 0, (buf))
#define FieldElementToByte(buf, bytelen, ele) mpz_export_padded(buf, bytelen, ele)

#define ByteToNumber(ele, bytelen, buf) mpz_import((*ele), bytelen, 1, sizeof((buf)[0]), 0, 0, (buf))
#define NumberToByte(buf, bytelen, ele) mpz_export_padded(buf, bytelen, ele)


#define SampleFieldElementFromBytes(ele, buf, bytelen) ByteToFieldElement(ele, bytelen, buf)

#define FieldSampleRandomGenerator(g, div, params) SampleRandomGenerator(g, div, (&params))


#define GetRandomNumber(ele, bits, params) GetRandomMpzt(ele, bits, (&params))
#else

#ifdef OTEXT_USE_PRIMEFIELD
typedef ECn fieldelement;
typedef ebrick brickexp;


#else
typedef EC2 fieldelement;
typedef ebrick2 brickexp;


#endif


typedef Big number;

#define FieldInit(secparam, seed, param) MiraclInit(secparam, seed, (&param))
#define FieldCleanup(param) MiraclCleanup((&param))
#define FieldGetGenerator(g, params) MiraclInitPoint((g), *(params.eccparams.X), *(params.eccparams.Y))
#define BrickPowerMod(bg, res, x) Miraclmulbrick(bg, res, x.getbig())
#define BrickInit(br, base, params) MiraclInitBrick(br, base, (&params))
#define BrickDelete(br) Miraclbrickend(br)
#define FieldElementInit(fe)
#define FieldElementSet(dst,src) (dst)=(src)
#define FieldElementMul(res, a, b, params) { \
		res=a; \
		res+=b; \
}
#define FieldElementDiv(res, a, b, params) { \
		res=a; \
		res-=b; \
}
#define FieldElementPow(res, a, b, params) { \
		res=a; \
		res*=b; \
}


#ifdef OTEXT_USE_PRIMEFIELD
#define FieldElementDoublePowMul(res, b1, e1, b2, e2, m_fParams) ecurve_mult2(e1.getbig(), b1.get_point(), e2.getbig(), b2.get_point(), res.get_point())
#else
#define FieldElementDoublePowMul(res, b1, e1, b2, e2, m_fParams) ecurve2_mult2(e1.getbig(), b1.get_point(), e2.getbig(), b2.get_point(), res.get_point())
#endif

#define GetRandomNumber(ele, bits, params) GetRandomBig(ele, bits)


#define NumberSet(dst,src) copy(src.getbig(), dst.getbig())
#define NumberSetSI(dst,src) convert(src,dst.getbig())
#define NumberAdd(res, a, b) add(a.getbig(), b.getbig(), res.getbig())
#define NumberMul(res, a, b) multiply(a.getbig(), b.getbig(), res.getbig())
//res=a*b//multiply(a.getbig(), b.getbig(), res.getbig())

#define ByteToNumber(ele, bytelen, buf) bytes_to_big (bytelen, (const char*) buf, (ele)->getbig())
#define NumberToByte(buf, bytelen, ele)  big_to_bytes (bytelen, ele.getbig(), buf, true) //prepend leading zeros

#define ByteToFieldElement(ele, bytelen, buf) ByteArrayToPoint((ele), bytelen, buf)
#define FieldElementToByte(buf, bytelen, ele) PointToByteArray(buf, bytelen, ele)

//Sample
#define SampleFieldElementFromBytes(ele, buf, bytelen) SamplePointFromBytes(ele, buf, bytelen);

#define FieldSampleRandomGenerator(g, div, params) SampleRandomPoint(g, (&params))


#endif


#ifdef OTEXT_USE_GMP
		BOOL GMPInit(SECLVL lvl, BYTE* seed, fparams* params);
		BOOL GMPCleanup(fparams* params);
		// mpz_export does not fill leading zeros, thus a prepending of leading 0s is required
		void mpz_export_padded(BYTE* pBufIdx, int field_size, mpz_t to_export);
		void GetRandomMpzt(mpz_t& ele, int bits, fparams* param);
		void SampleRandomGenerator(mpz_t& gen, mpz_t& div, fparams* params);

#endif//#else
		BOOL MiraclInit(SECLVL secparam, BYTE* seed, fparams* params);
		BOOL MiraclCleanup(fparams* params);
		BOOL MiraclInitBrick(ebrick *brick, ECn point, fparams* param);
		BOOL MiraclInitBrick(ebrick2 *brick, EC2 point, fparams* param);
		void Miraclmulbrick(ebrick2 *bg, EC2& res, big x);
		void Miraclmulbrick(ebrick *bg, ECn& res, big z);
		void MiraclInitPoint(EC2 &point, Big x, Big y);
		void MiraclInitPoint(ECn &point, Big x, Big y);
		void Miraclbrickend(ebrick2 *bg);
		void Miraclbrickend(ebrick *bg);

		void PointToByteArray(BYTE* pBufIdx, int field_size, ECn point);
		void ByteArrayToPoint(ECn* point, int field_size, BYTE* pBufIdx);
		void PointToByteArray(BYTE* pBufIdx, int field_size, EC2 point);
		void ByteArrayToPoint(EC2* point, int field_size, BYTE* pBufIdx);

		void printepoint(epoint point);
		void GetRandomBig(Big &ele, int bits);

		void SampleRandomPoint(EC2 &point, fparams* params);
		void SampleRandomPoint(ECn &point, fparams* params);

		void SamplePointFromBytes(EC2 *point, BYTE* input, int inbytelen);
//#endif



#endif /* __MPCCYRPTO_H_ */
