/*
 * multiplicationmasking.h
 *
 *  Created on: May 13, 2013
 *      Author: mzohner
 */

#ifndef MULTIPLICATIONMASKING_H_
#define MULTIPLICATIONMASKING_H_

#include "maskingfunction.h"

#define RNDVALBITLEN 80

class MulMasking : public MaskingFunction
{
public:
	MulMasking(int numelements, int inbitlen, int prodbitlen, CBitVector* in)
	{
		m_nNumElements = numelements; //=K
		m_nInBitLength = inbitlen; //=length of x and u
		m_nProdBitLength = prodbitlen; //=bitlength of the resulting product
		m_vInput = in; //contains x and u, is 2-dim in case of the server and 1-dim in case of the client
		m_nMask = (1<<prodbitlen) -1;
	};

	//In total K' OTs will be performed
	void Mask(int progress, int processedOTs, CBitVector* values, CBitVector* snd_buf, BYTE version)
	{
		int strlen = processedOTs * m_nProdBitLength * m_nNumElements;
		int startpos = progress * m_nProdBitLength * m_nNumElements;
		//cout << "startpos = " << startPos << ", strlen = " << strlen << endl;
		//Copy the random elements in Zn into values[0]
		values[0].Copy(snd_buf[0].GetArr(), CEIL_DIVIDE(startpos,8), CEIL_DIVIDE(strlen, 8));

		uint64_t tmpval;
		for(int i = progress, valueid, shifts, sndbufpos=0; i < progress+processedOTs; i++)
		{
			valueid = i/m_nInBitLength;
			//shifts = i%m_nBitLength;

			for(int j = 0; j < m_nNumElements; j++, sndbufpos+=m_nProdBitLength)
			{
				//Get value assigned with OT
				tmpval = m_vInput->Get2D<uint64_t>(valueid, j);

				//Compute val*2^i to obtain the euclidean distance
				//tmpval = tmpval<<shifts; //shifting is done in the post-processing
				tmpval = (tmpval + values[0].Get2D<uint64_t>(i, j)) & m_nMask;
				values[1].Set2D<uint64_t>(tmpval, i, j);
				//tmpval = (tmpval + snd_buf[1].Get<uint64_t>(sndbufpos, m_nBitLength)) & m_nMask;
				//snd_buf[1].Set<uint64_t>(tmpval, sndbufpos, m_nBitLength);

			}
		}
		snd_buf[1].XORBits(values[1].GetArr() + CEIL_DIVIDE(startpos,8), 0, strlen);
	};

	void UnMask(int progress, int processedOTs, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf, BYTE version)
	{
		uint64_t tmpval, rcvedval;
		int strlen = processedOTs * m_nProdBitLength * m_nNumElements;
		int startpos = progress * m_nProdBitLength * m_nNumElements;
		int otlen = m_nNumElements * m_nProdBitLength;

		rcv_buf.XORBits(output.GetArr() + CEIL_DIVIDE(startpos, 8), 0, strlen);

		for(int i = progress, bufpos=0, valueid; i < progress + processedOTs; i++)
		{
			if(choices.GetBitNoMask(i))
			{
				output.SetBits(rcv_buf.GetArr()+CEIL_DIVIDE(bufpos, 8), i * otlen, otlen);
				/*valueid = i/m_nBitLength;
				for(int j = 0; j < m_nNumElements; j++, bufpos+=m_nBitLength)
				{
					tmpval = output.Get2D<uint64_t>(valueid, j);
					rcvedval = rcv_buf.Get<uint64_t>(bufpos, m_nBitLength);
					tmpval = rcvedval < tmpval ? m_nMask+1 - tmpval + rcvedval : rcvedval - tmpval;
					output.Set2D(tmpval, valueid, j);
				}*/
			}
			bufpos+=(m_nProdBitLength * m_nNumElements);
		}
	};


	void expandMask(CBitVector& out, BYTE* sbp, int offset, int processedOTs, int bitlength)
	{
		int numrndbits = m_nProdBitLength * m_nNumElements;
		//the CBitVector to store the random values in
		CBitVector rndvals(numrndbits);

		if(numrndbits <= AES_KEY_BITS)
		{
			for(int i = 0; i< processedOTs; i++, sbp+=AES_KEY_BYTES)
			{
				out.SetBits(sbp, (offset+i) * numrndbits, numrndbits);
			}
		}
		else
		{
			BYTE m_bBuf[AES_BYTES];
			BYTE ctr_buf[AES_BYTES] = {0};
			int* counter = (int*) ctr_buf;
			AES_KEY_CTX tkey;
			MPC_AES_KEY_INIT(&tkey);
			for(int i = 0, rem; i< processedOTs; i++, sbp+=AES_KEY_BYTES)
			{
				//Generate sufficient random bits
				MPC_AES_KEY_EXPAND(&tkey, sbp);
				for(counter[0] = 0; counter[0] < numrndbits/AES_BITS; counter[0]++)
				{
					MPC_AES_ENCRYPT(&tkey, m_bBuf, ctr_buf);
					rndvals.SetBits(m_bBuf, counter[0]*AES_BITS, AES_BITS);
				}
				//the final bits
				if((rem = numrndbits - (counter[0]*AES_BITS)) > 0)
				{
					MPC_AES_ENCRYPT(&tkey, m_bBuf, ctr_buf);
					rndvals.SetBits(m_bBuf, counter[0]*AES_BITS, rem);
				}
				//Copy random bits into output vector
				out.SetBits(rndvals.GetArr(), (offset + i) * numrndbits, numrndbits);

			}
		}
	}

private:
	CBitVector* m_vInput;
	int m_nNumElements;
	int m_nInBitLength;
	int m_nProdBitLength;
	uint64_t m_nMask;

};

#endif /* MULTIPLICATIONMASKING_H_ */
