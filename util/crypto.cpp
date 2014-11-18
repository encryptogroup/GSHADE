/*
 * crypto.cpp
 *
 *  Created on: Nov 01, 2013
 *      Author: mzohner
 */


//#ifdef OTEXT_USE_GMP
const char* ifcp1024 = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
const char* ifcg1024 = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
const char* ifcq1024 = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";

const char* ifcp2048 = "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F";
const char* ifcg2048 = "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA";
const char* ifcq2048 = "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";

const char* ifcp3072 = "4660194093823565506151007332698542081380390944320667936220310340292682538415201463451360005469701273992420569531194415296871671272562243754789577412471203509686259933515539120145538889500684305065682267020422897056483203401642088590732633756278140548667640739272073464322452643609409839498807131787408915921523565001045685221279165409792825261753615641493423723165471868882028678262386826730035778207616806238910696112513243832793252430036079010833108716296401084350809152423357477416465451376967706115065572717893335336664895800189754170750266169252030669114411476002012410621336179123441424048589750501111541393610787337793314723136089502117079738181113934544472215273637670210480814609550715859453809706797176331069587697357167970759889883398852942449568449890603652456531060380065260476714266615239827983706919432589669744367350756821903843388105282430635020233707272521317674908786962912228887786913664926989228941514639";
const char* ifcg3072 = "326984479748743614358878489890111032378521682641889472728164592588245254735528952815040417677135099463681521117067228131302984716932197927691804537047698386112034189358693637764887258325546424576668654933254773228919028116187485325776123548207630122958160311311825230114818910264101591293903307807790394765896174615027850669640300925521032111542648598127663424462192520490917608209583615366128345913820058976254028107968965281721876376153097516948596625654797921929621363755081263164203185942482227411046415127689226121648774535224687708280963930985498313715804706762069594298539593719253724193098201932449349224692341850008449711165375995101343314201170357859203662648251088921851885444086613889195257606710405156897225917687758015354941738963422772322756212536951044725465040734436163477969317027796051497934165333064621979305683254912099909723895352817468375097484456065145582788954244042708099846989842764657922387568064";
const char* ifcq3072 = "95729504467608377623766753562217147614989054519467474668915026082895293552781";
//#else
	//#ifdef OTEXT_USE_PRIMEFIELD
/* NIST p256 bit elliptic curve prime 2#256 */

char *ecp256 = (char *)"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
/* elliptic curve parameter B */
char *ecb256 = (char *)"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
/* elliptic curve - point of prime order (x,y) */
char *ecx256 = (char *)"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
char *ecy256 = (char *)"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

/* NIST p224 bit elliptic curve prime 2#224 */
char *ecp224 = (char *)"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001";
/* elliptic curve parameter B */
char *ecb224 = (char *)"b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4";
/* elliptic curve - point of prime order (x,y) */
char *ecx224 = (char *)"b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
char *ecy224 = (char *)"bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";

/* p160 bit elliptic curve prime */
char *ecp160 = (char *) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF";
/* elliptic curve parameter B */
char *ecb160 = (char *) "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45";
/* elliptic curve - point of prime order (x,y) */
char *ecx160 = (char *) "4A96B5688EF573284664698968C38BB913CBFC82";
char *ecy160 = (char *) "23A628553168947D59DCC912042351377AC5FB32";
	//#else

char *ecx163 = (char *) "2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8";
char *ecy163 = (char *) "289070fb05d38ff58321f2e800536d538ccdaa3d9";

char *ecx233 = (char *) "17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126";
char *ecy233 = (char *) "1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3";

char *ecx283 = (char *) "503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836";
char *ecy283 = (char *) "1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259";
//	#endif
//#endif


#include "crypto.h"


#ifdef OTEXT_USE_GMP
BOOL GMPInit(SECLVL lvl, BYTE* seed, fparams* params) {
	mpz_init(params->ifcparams.p);
	mpz_init(params->ifcparams.g);
	mpz_init(params->ifcparams.q);

	if(lvl.ifcbits == ST.ifcbits)
	{
		mpz_set_str(params->ifcparams.p, ifcp1024, 16);	mpz_set_str(params->ifcparams.g, ifcg1024, 16);
		mpz_set_str(params->ifcparams.q, ifcq1024, 16); params->secparam = 1024;
	} else if(lvl.ifcbits == MT.ifcbits)
	{
		mpz_set_str(params->ifcparams.p, ifcp2048, 16);	mpz_set_str(params->ifcparams.g, ifcg2048, 16);
		mpz_set_str(params->ifcparams.q, ifcq2048, 16); params->secparam = 2048;
	} else if(lvl.ifcbits == LT.ifcbits)
	{
		mpz_set_str(params->ifcparams.p, ifcp3072, 10);	mpz_set_str(params->ifcparams.g, ifcg3072, 10);
		mpz_set_str(params->ifcparams.q, ifcq3072, 10); params->secparam = 3072;
	} else //Short term security
	{
		mpz_set_str(params->ifcparams.p, ifcp1024, 16);	mpz_set_str(params->ifcparams.g, ifcg1024, 16);
		mpz_set_str(params->ifcparams.q, ifcq1024, 16);	params->secparam = 1024;
	}

	/*switch (lvl.ifcbits)
	{
	case ST.ifcbits:
		mpz_set_str(m_NPState.p, ifcp1024, 16);	mpz_set_str(m_NPState.g, ifcg1024, 16);	mpz_set_str(m_NPState.q, ifcq1024, 16); m_nSecParam = 1024; break;
	case MT.ifcbits:
		mpz_set_str(m_NPState.p, ifcp2048, 16);	mpz_set_str(m_NPState.g, ifcg2048, 16);	mpz_set_str(m_NPState.q, ifcq2048, 16); m_nSecParam = 2048; break;
	case LT.ifcbits:
		mpz_set_str(m_NPState.p, ifcp3072, 10);	mpz_set_str(m_NPState.g, ifcg3072, 10);	mpz_set_str(m_NPState.q, ifcq3072, 10); m_nSecParam = 3072; break;
	default:
		mpz_set_str(m_NPState.p, ifcp1024, 16);	mpz_set_str(m_NPState.g, ifcg1024, 16);	mpz_set_str(m_NPState.q, ifcq1024, 16);	m_nSecParam = 1024; break;
	}*/

	//TODO: Seed gmp from seed using gmp_randseed (gmp randstate t state, mpz t seed )
	gmp_randinit_mt (params->ifcparams.rnd_state );
	params->elebytelen = (params->secparam+7)/8;//(mpz_sizeinbase(m_NPState.p, 2)+7)/8;
	//m_NPField.secparam  = m_nSecParam;

	return true;
}

BOOL GMPCleanup(fparams* params) {
	//TODO: Further cleanup
	gmp_randclear(params->ifcparams.rnd_state);
	return TRUE;
}
#endif

BOOL MiraclInit(SECLVL lvl, BYTE* seed, fparams* params) {
	//secparam = 163;

/*	switch(lvl.ecckcbits)
	{
#ifdef OTEXT_USE_PRIMEFIELD
		case ST: m_nSecParam = 160; break;
		case MT: m_nSecParam = 224; break;
		case LT: m_nSecParam = 256; break;
		default: m_nSecParam = 160; break;
#else
		case ST.ecckcbits: m_nSecParam = 163; break;
		case MT.ecckcbits: m_nSecParam = 233; break;
		case LT.ecckcbits: m_nSecParam = 283; break;
		default: m_nSecParam = 163; break;
#endif
	}*/
#ifdef OTEXT_USE_PRIMEFIELD
	params->secparam = lvl.ecckcbits;
#else
	params->secparam= lvl.ecckcbits;
#endif

	miracl *mip = mirsys(params->secparam, 2);

	//miracl *mip=mirsys(MR_ROUNDUP(abs(163),4),16);
	char *ecp = NULL, *ecb = NULL, *ecx = ecx160, *ecy = ecy160;
	params->eccparams.BB = new Big();
	params->eccparams.BA = new Big();
	params->eccparams.BP = new Big();



#ifdef OTEXT_USE_PRIMEFIELD
	if(lvl.eccpfbits == ST.eccpfbits)
	{
		ecp = ecp160;	ecb = ecb160;	ecx = ecx160;	ecy = ecy160;
	} else if(lvl.eccpfbits == MT.eccpfbits)
	{
		ecp = ecp224;	ecb = ecb224;	ecx = ecx224;	ecy = ecy224;
	} else if(lvl.eccpfbits == LT.eccpfbits)
	{
		ecp = ecp256;	ecb = ecb256;	ecx = ecx256;	ecy = ecy256;
	} else //Short term security
	{
		ecp = ecp160;	ecb = ecb160;	ecx = ecx160;	ecy = ecy160;
	}
	/*switch (lvl.eccpfbits)
	{
	case ST.eccpfbits:
		ecp = ecp160;	ecb = ecb160;	ecx = ecx160;	ecy = ecy160;	break;
	case MT.eccpfbits:
		ecp = ecp224;	ecb = ecb224;	ecx = ecx224;	ecy = ecy224;	break;
	case LT.eccpfbits:
		ecp = ecp256;	ecb = ecb256;	ecx = ecx256;	ecy = ecy256;	break;
	default: //Short term security
		ecp = ecp160;	ecb = ecb160;	ecx = ecx160;	ecy = ecy160;	break;
	}*/
#else
	if(lvl.ecckcbits == ST.ecckcbits)
	{
		ecx = ecx163;	ecy = ecy163;	params->eccparams.m = 163;	params->eccparams.a = 7;
		params->eccparams.b = 6;	params->eccparams.c = 3;	*(params->eccparams.BA) = 1;
	} else if(lvl.ecckcbits == MT.ecckcbits)
	{
		ecx = ecx233;	ecy = ecy233;	params->eccparams.m = 233;	params->eccparams.a = 74;
		params->eccparams.b = 0;	params->eccparams.c = 0;	*(params->eccparams.BA) = 0;
	} else if(lvl.ecckcbits == LT.ecckcbits)
	{
		ecx = ecx283;	ecy = ecy283;	params->eccparams.m = 283;	params->eccparams.a = 12;
		params->eccparams.b = 7;	params->eccparams.c = 5;	*(params->eccparams.BA) = 0;
	} else //Short term security
	{
		ecx = ecx163;	ecy = ecy163;	params->eccparams.m = 163;	params->eccparams.a = 7;
		params->eccparams.b = 6;	params->eccparams.c = 3; 	*(params->eccparams.BA) = 1;
	}
	/*switch (lvl.ecckcbits)
	{
	case ST.ecckcbits:
		ecx = ecx163;	ecy = ecy163;	m_nM = 163;	m_nA = 7;	m_nB = 6;	m_nC = 3;	*m_BA = 1;	break;
	case MT.ecckcbits:
		ecx = ecx233;	ecy = ecy233;	m_nM = 233;	m_nA = 74;	m_nB = 0;	m_nC = 0;	*m_BA = 0;	break;
	case LT.ecckcbits:
		ecx = ecx283;	ecy = ecy283;	m_nM = 283;	m_nA = 12;	m_nB = 7;	m_nC = 5;	*m_BA = 0;	break;
	default:
		ecx = ecx163;	ecy = ecy163;	m_nM = 163;	m_nA = 7;	m_nB = 6;	m_nC = 3; 	*m_BA = 1;	break;
	}*/
#endif
	//seed the miracl rnd generator
	irand((long)(*seed));

	//Change the base to read in the parameters
	mip->IOBASE = 16;
	*(params->eccparams.BB) = 1;

#ifdef OTEXT_USE_PRIMEFIELD
	mip->IOBASE = 16;
	*(m_ECCField.BA) = -3;
	*(m_ECCField.BB) = ecb;
	*(m_ECCField.BP) = ecp;
	ecurve(*(m_ECCField.BA), *(m_ECCField.BB), *(m_ECCField.BP), MR_BEST);
#else
	ecurve2_init(params->eccparams.m, params->eccparams.a, params->eccparams.b, params->eccparams.c,
			params->eccparams.BA->getbig(), params->eccparams.BB->getbig(), false, MR_BEST);
#endif

	params->eccparams.X = new Big();
	params->eccparams.Y = new Big();
	*(params->eccparams.X) = ecx;
	*(params->eccparams.Y) = ecy;

	//cout << "params->eccparams.X : " << (*params->eccparams.X) << endl;

	//reset the base representation
	//mip->IOBASE = 10;

	//For ECC, a coordinate is transferred as well as a 1/-1
	params->elebytelen = (params->secparam+7)/8 + 1;

	return true;
}

BOOL MiraclCleanup(fparams* params)
{
	delete params->eccparams.Y;
	delete params->eccparams.X;
	delete params->eccparams.BA;
	delete params->eccparams.BB;
	delete params->eccparams.BP;

	mirexit();

	return TRUE;
}





void Miraclbrickend(ebrick2* bg)
{
	ebrick2_end(bg);
}

void Miraclbrickend(ebrick* bg)
{
	ebrick_end(bg);
}

void MiraclInitPoint(EC2& point, Big x, Big y)
{
	point = EC2(x, y);
}

void MiraclInitPoint(ECn& point, Big x, Big y)
{
	point = ECn(x, y);
}

void GetRandomBig(Big& ele, int bits)
{
	ele = rand(bits, 2);
}

#ifdef OTEXT_USE_GMP
//Get random value that is in sub-field q
void GetRandomMpzt(mpz_t& ele, int bits, fparams* param)
{
	mpz_urandomm(ele, param->ifcparams.rnd_state, param->ifcparams.q);
	//mpz_mod(ele, ele, param->ifcparams.q);
}
#endif

BOOL MiraclInitBrick(ebrick* brick, ECn point, fparams* param)
{
	Big x, y;
	point.getxy(x, y);
	return ebrick_init(brick, x.getbig(), y.getbig(), param->eccparams.BA->getbig(), param->eccparams.BB->getbig(),
			param->eccparams.BP->getbig(), 8, param->secparam);
}

BOOL MiraclInitBrick(ebrick2* brick, EC2 point, fparams* param)
{
	Big x, y;
	point.getxy(x, y);
	return ebrick2_init(brick, x.getbig(), y.getbig(), param->eccparams.BA->getbig(), param->eccparams.BB->getbig(),
			param->eccparams.m, param->eccparams.a, param->eccparams.b, param->eccparams.c, 8, param->secparam);
}


void Miraclmulbrick(ebrick2* bg, EC2& result, big e)
{
	Big xtmp, ytmp;
	mul2_brick(bg, e, xtmp.getbig(), ytmp.getbig());
	MiraclInitPoint(result, xtmp, ytmp);
}

void Miraclmulbrick(ebrick* bg, ECn& result, big e)
{
	Big xtmp, ytmp;
	mul_brick(bg, e, xtmp.getbig(), ytmp.getbig());
	MiraclInitPoint(result, xtmp, ytmp);
}


/*BOOL BaseOT::Miracl_InitBrick2(ebrick2* brick, ECn* point)
{
	Big x, y;
	point->getxy(x, y);
	return ebrick2_init(brick, x.getbig(), y.getbig(), m_BA->getbig(), m_BB->getbig(), m_nM, m_nA, m_nB, m_nC, 8, m_nSecParam);
}*/


void printepoint(epoint point)
{
	Big x, y;
	epoint_getxyz(&point,x.getbig(),y.getbig(),NULL);
	cout << "(" << x << ", " << y << ")" << endl;
}


void PointToByteArray(BYTE* pBufIdx, int field_size, ECn point)
{
	int itmp;
	Big bigtmp;
	//compress to x-point and y-bit and convert to byte array
	itmp = point.get(bigtmp);

	//first store the y-bit
	pBufIdx[0] = (BYTE) (itmp & 0x01);

	//then store the x-coordinate (sec-param/8 byte size)
	big_to_bytes(field_size-1, bigtmp.getbig(), (char*) pBufIdx+1, true);
}

void ByteArrayToPoint(ECn *point, int field_size, BYTE* pBufIdx) {
	int itmp;
	Big bigtmp;
	itmp = (int) (pBufIdx[0]);

	bytes_to_big(field_size-1, (const char*) pBufIdx + 1, bigtmp.getbig());
	*point = ECn(bigtmp, itmp);
}


void PointToByteArray(BYTE* pBufIdx, int field_size, EC2 point)
{
	int itmp;
	Big bigtmp;
	//compress to x-point and y-bit and convert to byte array
	itmp = point.get(bigtmp);

	//first store the y-bit
	pBufIdx[0] = (BYTE) (itmp & 0x01);

	//then store the x-coordinate (sec-param/8 byte size)
	big_to_bytes(field_size-1, bigtmp.getbig(), (char*) pBufIdx+1, true);

}

void ByteArrayToPoint(EC2 *point, int field_size, BYTE* pBufIdx) {
	int itmp;
	Big bigtmp;
	itmp = (int) (pBufIdx[0]);

	bytes_to_big(field_size-1, (const char*) pBufIdx + 1, bigtmp.getbig());
	*point = EC2(bigtmp, itmp);
}

void SampleRandomPoint(EC2 &point, fparams* params) {

	Big bigtmp;
	int itmp = rand()%2;
	do
	{
		bigtmp = rand(params->secparam, 2);
		point = EC2(bigtmp, itmp);
	}
	while (point_at_infinity(point.get_point()));
}


void SampleRandomPoint(ECn &point, fparams* params) {
	Big bigtmp;
	int itmp = rand()%2;
	do
	{
		bigtmp = rand(params->secparam, 2);
		point = ECn(bigtmp, itmp);
	}
	while (point_at_infinity(point.get_point()));
}

void SamplePointFromBytes(EC2 *point, BYTE* input, int inbytelen) {
	Big bigtmp;
	bytes_to_big (inbytelen, (const char*) input, bigtmp.getbig());//(bigtmp, inbytelen, input);
	premult(bigtmp.getbig(), MAXMSGSAMPLE, bigtmp.getbig());
	for(int i = 0; i < MAXMSGSAMPLE; i++)
	{
		*point = EC2(bigtmp, 0);
		if(!point_at_infinity(point->get_point()))
			return;
		*point = EC2(bigtmp, 1);
		if(!point_at_infinity(point->get_point()))
			return;
		incr(bigtmp.getbig(), 1, bigtmp.getbig());
	}
	cerr << "Error while sampling point, exiting!" << endl;
	exit(0);
}

#ifdef OTEXT_USE_GMP
// mpz_export does not fill leading zeros, thus a prepending of leading 0s is required
void mpz_export_padded(BYTE* pBufIdx, int field_size, mpz_t to_export) {
	size_t size = 0;
	mpz_export(pBufIdx, &size, 1, sizeof(pBufIdx[0]), 0, 0, to_export);

	if (size < field_size) {
		for (int i = 0; i + size < field_size; i++) {
			pBufIdx[i] = 0;
		}
		pBufIdx += (field_size - size);
		mpz_export(pBufIdx, &size, 1, sizeof(pBufIdx[0]), 0, 0, to_export);
	}
}

void SampleRandomGenerator(mpz_t& gen, mpz_t& div, fparams* params)
{
	mpz_t tmp;
	mpz_init(tmp);
	//sample random hi -- sample random element x in Zp, and then compute x^{(p-1)/q} mod p
	do
	{
		mpz_urandomb(tmp, params->ifcparams.rnd_state, params->secparam);
		mpz_mod(tmp, tmp, params->ifcparams.p);
		mpz_powm(gen, tmp, div, params->ifcparams.p);
	} while(!(mpz_cmp_ui(gen, (unsigned long int) 1) )  );
}
#endif

