#ifndef _MPC_H_
#define _MPC_H_

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../ot/naor-pinkas.h"
#include "../ot/asharov-lindell.h"
#include "../ot/ot-extension.h"
#include "../util/cbitvector.h"
#include "../ot/shademasking.h"
#include "../ot/multiplicationmasking.h"

#include <vector>
#include <sys/time.h>

#include <limits.h>
#include <iomanip>
#include <string>

using namespace std;


static const char* m_nSeedA = "4373984170123878137145641001";
static const char* m_nSeedB = "6843248634584234214808404631";
const char* m_nSeed;

#define IDSERVER 0
#define IDCLIENT 1


USHORT		m_nPort = 7766;
const char* m_nAddr ;// = "localhost";

BOOL Init();
BOOL Cleanup();
BOOL Connect();
BOOL Listen();

void InitOTSender(const char* address, int port);
void InitOTReceiver(const char* address, int port);

BOOL PrecomputeNaorPinkasSender();
BOOL PrecomputeNaorPinkasReceiver();
BOOL ObliviouslyReceive(CBitVector& R, CBitVector& X_R, int numOTs, int bitlength);
BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength);
void ComputeHD(CBitVector& input, CBitVector& output, int numOTs, int dbsize, int modulus);
void SumValuesHD(CBitVector& input, CBitVector& sum, int modulus, int dima, int dimb);
void ComputeMult(CBitVector& input, CBitVector& output, int numOTs, int dbsize, int elementlen, int resbitlen);
void SumValuesMult(CBitVector& input, CBitVector& sum, int outbitlen, int numvals, int dima, int dimb);
void ReconstructOutput(CBitVector& input, CBitVector& output, int numelements, int bitlength);

void ComputeED(CBitVector& input, CBitVector& output, int numvals, int dbsize, int elementlen);
void ComputeSP(CBitVector& input, CBitVector& output, int dimvec, int dimproj, int inbitlen);
void ComputeSquare(CBitVector& input, CBitVector& output, int numelements);
void ComputeDouble(CBitVector& input, CBitVector& output, int numelements);
void testEigenfaces(int Kdash, int bitlen, int K, int dbsize);
void testEuclideanDistance(int K, int bitlen, int dbsize);
void testHammingDistance(int idxlen, int dbsize);


void testRoutine();


// Network Communication
vector<CSocket> m_vSockets;
int m_nPID; // thread id
int m_nSecParam; 
SECLVL m_sSecLvl;
int m_nBitLength;
int m_nMod;
MaskingFunction* m_fMaskFct;

// Naor-Pinkas OT
BaseOT* bot;
OTExtensionSender *sender;
OTExtensionReceiver *receiver;
CBitVector U; 
BYTE *vKeySeeds;
BYTE *vKeySeedMtx;

int m_nNumOTThreads;

// SHA PRG
BYTE				m_aSeed[SHA1_BYTES];
int			m_nCounter;
double			rndgentime;


#endif //_MPC_H_
