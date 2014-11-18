/*
 * baseOT.h
 *
 *  Created on: Mar 20, 2013
 *      Author: mzohner
 */

#ifndef BASEOT_H_
#define BASEOT_H_

#include "../util/typedefs.h"
#include "../util/cbitvector.h"
#include "../util/socket.h"
#include <ctime>

#include <iostream>
#include <cstring>
#include <fstream>
#include <time.h>
#include "../util/crypto.h"

class BaseOT
{
	public:
		BaseOT(){};
		virtual ~BaseOT(){};

		
		BOOL Init(SECLVL sec, BYTE* seed)
		{
			return FieldInit(sec, seed, m_fParams);
		}
		
		BOOL Cleanup()
		{
			return FieldCleanup(m_fParams);
		}


		virtual BOOL 			Sender(int nSndVals, int nOTs, CSocket& sock, BYTE* ret) = 0;
		virtual BOOL 			Receiver(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret) = 0;

protected:

		//int m_nSecParam;
		fparams m_fParams;
		//int m_nFEByteLen;

		//Big *m_BA, *m_BB, *m_BP;
		//Big *m_X, *m_Y;

		//int m_nM, m_nA, m_nB, m_nC;

		void hashReturn(BYTE* ret, BYTE* val, int val_len, int ctr) {
			HASH_CTX sha;
			MPC_HASH_INIT(&sha);
			MPC_HASH_UPDATE(&sha, (BYTE*) val, val_len);
			MPC_HASH_UPDATE(&sha, (BYTE*) &ctr, sizeof(int));
			MPC_HASH_FINAL(&sha, ret);

		}




};

#endif /* BASEOT_H_ */
