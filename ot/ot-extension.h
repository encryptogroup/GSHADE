/*
 * Methods for the OT Extension routine
 */

#ifndef __OT_EXTENSION_H_
#define __OT_EXTENSION_H_

#include "../util/typedefs.h"
#include "../util/socket.h"
#include "../util/thread.h"
#include "../util/cbitvector.h"
#include "../util/crypto.h"
#include "maskingfunction.h"


//#define DEBUG

const BYTE	G_OT = 0x01;
const BYTE 	C_OT = 0x02;
const BYTE	R_OT = 0x03;
const BYTE	S_OT = 0x04;
const BYTE OCRS_OT = 0x05;

typedef struct OTBlock_t {
	int blockid;
	int processedOTs;
	BYTE* snd_buf;
	OTBlock_t* next;
} OTBlock;

static void InitAESKey(AES_KEY_CTX* ctx, BYTE* keybytes, int numkeys)
{
	BYTE* pBufIdx = keybytes;
	for(int i=0; i<numkeys; i++ )
	{
		MPC_AES_KEY_INIT(ctx+i);
		MPC_AES_KEY_EXPAND(ctx+i, pBufIdx);
		pBufIdx += AES_KEY_BYTES;
	}
}


class OTExtensionSender {
/*
 * OT sender part
 * Input: 
 * ret: returns the resulting bit representations. Has to initialized to a byte size of: nOTs * nSndVals * state.field_size
 * 
 * CBitVector* values: holds the values to be transferred. If C_OT is enabled, the first dimension holds the value while the delta is written into the second dimension
 * Output: was the execution successful?
 */
  public:
	OTExtensionSender(int nSndVals, int nOTs, int bitlength, int symsecparam, CSocket* sock, CBitVector& U, BYTE* keybytes,
			CBitVector& x0, CBitVector& x1,	BYTE type) {
		m_nSndVals = nSndVals;
		m_nOTs = nOTs; 
		m_nSockets = sock;
		m_nU = U;
		m_vValues = (CBitVector*) malloc(sizeof(CBitVector) * 2);
		m_vValues[0] = x0;
		m_vValues[1] = x1;
		m_nBitLength = bitlength;
		m_bProtocol = type;
		m_nCounter = 0;
		m_nSymSecParam = symsecparam;
		m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nSymSecParam);
		m_lSendLock = new CLock;
		InitAESKey(m_vKeySeeds, keybytes, m_nSymSecParam);
	};


	OTExtensionSender(int nSndVals, int symsecparam, CSocket* sock, CBitVector& U, BYTE* keybytes) {
		m_nSndVals = nSndVals;
		m_nSockets = sock;
		m_nU = U;
		m_nCounter = 0;
		m_nSymSecParam = symsecparam;
		m_vValues = (CBitVector*) malloc(sizeof(CBitVector) * nSndVals);
		m_vKeySeeds = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nSymSecParam);
		m_lSendLock = new CLock;
		InitAESKey(m_vKeySeeds, keybytes, m_nSymSecParam);
	};
	
	~OTExtensionSender(){free(m_vKeySeeds);};
	BOOL send(int numOTs, int bitlength, CBitVector& s0, CBitVector& s1, BYTE type, int numThreads, MaskingFunction* maskfct);
	BOOL send(int numThreads);

	BOOL OTSenderRoutine(int id, int myNumOTs);
	void BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, int blocksize, BYTE* ctr);
	void ProcessAndEnqueue(CBitVector* snd_buf, int id, int progress, int processedOTs);
	void SendBlocks(int numThreads);
	void MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, int ctr, int processedOTs);
	BOOL verifyOT(int myNumOTs);



  protected:
	BYTE m_bProtocol;
  	int m_nSndVals;
  	int m_nOTs;
  	int m_nBitLength;
  	int m_nCounter;
  	int m_nBlocks;
  	int m_nSymSecParam;
  	CSocket* m_nSockets;
  	CBitVector m_nU;
  	CBitVector* m_vValues;
  	MaskingFunction* m_fMaskFct;
  	AES_KEY_CTX* m_vKeySeeds;
  	OTBlock* m_sBlockHead;
  	OTBlock* m_sBlockTail;
  	CLock* m_lSendLock;

	class OTSenderThread : public CThread {
	 	public:
	 		OTSenderThread(int id, int nOTs, OTExtensionSender* ext) {senderID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTSenderThread(){};
			void ThreadMain() {success = callback->OTSenderRoutine(senderID, numOTs);};
		private: 
			int senderID; 
			int numOTs;
			OTExtensionSender* callback;
			BOOL success;
	};

};



class OTExtensionReceiver {
/*
 * OT receiver part
 * Input: 
 * nSndVals: perform a 1-out-of-nSndVals OT
 * nOTs: the number of OTs that shall be performed
 * choices: a vector containing nBaseOTs choices in the domain 0-(SndVals-1) 
 * ret: returns the resulting bit representations, Has to initialized to a byte size of: nOTs * state.field_size
 * 
 * Output: was the execution successful?
 */
  public:
	OTExtensionReceiver(int nSndVals, int nOTs, int bitlength, int symsecparam, CSocket* sock,
			BYTE* keybytes, CBitVector& choices, CBitVector& ret, BYTE protocol, BYTE* seed) {
		m_nSndVals = nSndVals;
		m_nOTs = nOTs; 
		m_nSockets = sock;
		m_nChoices = choices;
		m_nRet = ret;
		m_nSeed = seed;
		m_nBitLength = bitlength;
		m_bProtocol = protocol;
		m_nCounter = 0;
		m_nSymSecParam = symsecparam;
		m_vKeySeedMtx = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nSymSecParam * nSndVals);
		InitAESKey(m_vKeySeedMtx, keybytes, m_nSymSecParam * nSndVals);
	};
	OTExtensionReceiver(int nSndVals, int symsecparam, CSocket* sock, BYTE* keybytes, BYTE* seed) {
		m_nSndVals = nSndVals;
		m_nSockets = sock;
		//m_nKeySeedMtx = vKeySeedMtx;
		m_nSymSecParam = symsecparam;
		m_nSeed = seed;
		m_nCounter = 0;
		m_vKeySeedMtx = (AES_KEY_CTX*) malloc(sizeof(AES_KEY_CTX) * m_nSymSecParam * nSndVals);
		InitAESKey(m_vKeySeedMtx, keybytes, m_nSymSecParam * nSndVals);
	};
	~OTExtensionReceiver(){free(m_vKeySeedMtx); };


	BOOL receive(int numOTs, int bitlength, CBitVector& choices, CBitVector& ret, BYTE type,
			int numThreads, MaskingFunction* maskfct);

	BOOL receive(int numThreads);
	BOOL OTReceiverRoutine(int id, int myNumOTs);
	//void ReceiveAndProcess(CBitVector& vRcv, CBitVector& seedbuf, int id, int ctr, int lim);
	void ReceiveAndProcess(int numThreads);
	void BuildMatrices(CBitVector& T, CBitVector& SndBuf, int numblocks, int ctr, BYTE* ctr_buf);
	void HashValues(CBitVector& T, CBitVector& seedbuf, int ctr, int lim);
	BOOL verifyOT(int myNumOTs);

  protected:
	BYTE m_bProtocol;
  	int m_nSndVals;
  	int m_nOTs;
  	int m_nBitLength;
  	int m_nCounter;
  	int m_nSymSecParam;
  	CSocket* m_nSockets;
  	CBitVector m_nChoices;
  	CBitVector m_nRet;
  	BYTE* m_nSeed;
  	MaskingFunction* m_fMaskFct;
  	AES_KEY_CTX* m_vKeySeedMtx;


	class OTReceiverThread : public CThread {
	 	public:
	 		OTReceiverThread(int id, int nOTs, OTExtensionReceiver* ext) {receiverID = id; numOTs = nOTs; callback = ext; success = false;};
	 		~OTReceiverThread(){};
			void ThreadMain() {success = callback->OTReceiverRoutine(receiverID, numOTs);};
		private: 
			int receiverID; 
			int numOTs;
			OTExtensionReceiver* callback;
			BOOL success;
	};

};

#endif
