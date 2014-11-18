/*
 * Compute the Naor-Pinkas Base OTs
 */

#ifndef __Naor_Pinkas_H_
#define __Naor_Pinkas_H_

#include "baseOT.h"

class NaorPinkas : public BaseOT
{

	public:

	NaorPinkas(){};
	~NaorPinkas(){};
	
	NaorPinkas(SECLVL sec, BYTE* seed){Init(sec, seed);};

	BOOL Receiver(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	BOOL Sender(int nSndVals, int nOTs, CSocket& sock, BYTE* ret);

	
};
		


#endif
