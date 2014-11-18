/*
 * The Naor-Pinkas OT protocol that does not require a random oracle
 */

#ifndef __Naor_Pinkas_NORO_H_
#define __Naor_Pinkas_NORO_H_

#include "baseOT.h"

class NaorPinkasNoRO : public BaseOT
{

	public:

	NaorPinkasNoRO(){};
	~NaorPinkasNoRO(){};
	
	NaorPinkasNoRO(SECLVL sec, BYTE* seed){Init(sec, seed);};
	
	BOOL Receiver(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	BOOL Sender(int nSndVals, int nOTs, CSocket& sock, BYTE* ret);

	
};
		


#endif
