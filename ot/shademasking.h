/*
 * SHADEMasking.h
 *
 *  Created on: May 13, 2013
 *      Author: mzohner
 */

#ifndef SHADEMASKING_H_
#define SHADEMASKING_H_

#include "maskingfunction.h"

#define RNDVALBITLEN 80

class SHADEMasking : public MaskingFunction
{
public:


	SHADEMasking(int numelements, int modulus, CBitVector* in)
	{
		m_nNumElements = numelements;
		m_nMod = modulus;
		int tmpbitlen = CEIL_LOG2(modulus);
		m_nBitsMod = tmpbitlen;
		//if p is a power of two, random values can be generated easily. if not, add
		//additional bits of entropy
		if(modulus == (1<<tmpbitlen)) {
			m_nBitLength = tmpbitlen;
			m_bCompress=false;
			cout << "not compressing" << endl;
		} else {
			m_nBitLength = RNDVALBITLEN;//CEIL_DIVIDE(tmpbitlen + RNDVALBITLEN,8)*8;
			m_nIters = (RNDVALBITLEN>>3)/sizeof(USHORT);
			m_bCompress=true;
		}
		m_vInput = in;
	};

	void Mask(int progress, int processedOTs, CBitVector* values, CBitVector* snd_buf, BYTE version)
	{
		int bitPos = progress * m_nNumElements;
		int startPos = progress * m_nBitsMod * m_nNumElements;
		int strlen = processedOTs * m_nBitsMod * m_nNumElements;
		//cout << "startpos = " << startPos << ", strlen = " << strlen << endl;
		//Copy the random elements in Zn into values[0]
		values[0].Copy(snd_buf[0].GetArr(), CEIL_DIVIDE(startPos,8), CEIL_DIVIDE(strlen, 8));

		for(int i = 0, elementPos = startPos; i < processedOTs; i++) {
			bitPos = progress;
			for(int k = 0; k < m_nNumElements; k++, elementPos+=m_nBitsMod, bitPos+=m_nBitsMod) {
				//Get the random mask
				//int m1 = values[0].Get<int>(elementPos, m_nBitsMod);
				int m1 = values[0].Get2D<int>(i+progress, k);
				//Get deltabit
				int v = m_vInput->GetBitNoMask(bitPos);
				int cor = rem((v + m1), m_nMod);
				//values[1].Set<int>(cor, elementPos, m_nBitsMod);
				values[1].Set2D<int>(cor, i+progress, k);
				//cout << "Setting cor = " << (hex) << cor << (dec) << " at " << i+progress << ", " << k
				//		<< ", with bit = " << (unsigned int) m_vInput->GetBitNoMask(bitPos) << ", and bitpos = " << bitPos << endl;
				int m2 = snd_buf[1].Get<int>(((i * m_nNumElements) + k)*m_nBitsMod, m_nBitsMod);
				//int m2 = snd_buf[1].Get<int>(i, k);
				int v2 = rem((cor + m2), m_nMod);

				//snd_buf[1].Set<int>(v2, i, k);
				snd_buf[1].Set<int>(v2, ((i * m_nNumElements) + k) * m_nBitsMod, m_nBitsMod);
				//Store the result in values[0]
				//values[1].Set<int>(v3, elementPos, m_nBitsMod);
			}
		}
		//snd_buf[0].PrintHex();
		//snd_buf[1].PrintHex();
		//snd_buf[1].XORBytes(values[1].GetArr()+CEIL_DIVIDE(startPos, 8), 0, CEIL_DIVIDE(strlen, 8));
		//m_vInput->PrintBinary();
		//values[0].PrintHex();
		//values[1].PrintHex();
	};

	void UnMask(int progress, int processedOTs, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf, BYTE version)
	{
		int bitPos = progress * m_nNumElements;
		int globalStartPos = progress * m_nBitsMod * m_nNumElements;
		int strlen = processedOTs * m_nBitsMod * m_nNumElements;

		//output.PrintHex();

		for(int i= 0, globalPos = globalStartPos, pos = 0; i < processedOTs;  i++)
		{
			if(choices.GetBitNoMask(i+progress))
			{
				for(int k = 0; k < m_nNumElements; k++, globalPos+=m_nBitsMod, bitPos +=m_nBitsMod)
				{
					int mask = output.Get2D<int>(i+progress, k);
					int rcved = rcv_buf.Get<int>(bitPos, m_nBitsMod);
					int val = rem((rcved - mask), m_nMod);
					output.Set2D<int>(val, i+progress, k);//globalPos, m_nBitsMod);
					//sum = output.Get<int>(pos, m_nBitLength)  % m_nMod;
					//sum = rem(rcv_buf.Get<int>(pos - startPos, m_nBitLength) - sum, m_nMod);
					//output.Set(sum, pos, m_nBitLength);
				}
			}
			else
			{
				//Do nothing - the random value has already been generated
				globalPos = globalPos + (m_nNumElements * m_nBitsMod);
				bitPos = bitPos + (m_nNumElements * m_nBitsMod);
			}
		}
	};


	void expandMask(CBitVector& out, BYTE* sbp, int offset, int processedOTs, int bitlength)
	{
		int numrndbits = m_nBitLength * m_nNumElements;
		//the CBitVector to store the random values in
		CBitVector rndvals(numrndbits);

		if(numrndbits <= AES_KEY_BITS)
		{
			for(int i = 0; i< processedOTs; i++, sbp+=AES_KEY_BYTES)
			{
				rndvals.SetBits(sbp, 0, numrndbits);
				GenerateZNValsFromBytes(out, rndvals, offset + i, bitlength);
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
				MPC_AES_KEY_EXPAND(&tkey, sbp);
				for(counter[0] = 0; counter[0] < numrndbits/AES_BITS; counter[0]++)
				{
					MPC_AES_ENCRYPT(&tkey, m_bBuf, ctr_buf);
					rndvals.SetBits(m_bBuf, counter[0]*AES_BITS, AES_BITS);
				}
				//rndvals.PrintHex();
				//the final bits
				//cout << "bits: " << (counter*AES_BITS) << ", bitlength: " << m_nBitLength << endl;
				if((rem = numrndbits - (counter[0]*AES_BITS)) > 0)
				{
					MPC_AES_ENCRYPT(&tkey, m_bBuf, ctr_buf);
					rndvals.SetBits(m_bBuf, counter[0]*AES_BITS, rem);
				}
				//rndvals.PrintHex();
				//Generate elements in Z_{modulus} from the expanded bits
				GenerateZNValsFromBytes(out, rndvals, offset + i, bitlength);

			}
		}
		//cout << "m_nBitLength = " << m_nBitsMod << ", m_nNumElements = " << m_nNumElements << endl;
		//rndvals.PrintHex();
		//out.PrintHex();
	}


	void GenerateZNValsFromBytes(CBitVector& out, CBitVector& rndbytes, int OTid, int bitlength) {
		if(m_bCompress) {
			for(int i = 0, ctr = 0; i < m_nNumElements; i++) {
				int tmpval = rem((int) rndbytes.Get<ushort>(ctr, sizeof(ushort)*8), m_nMod);
				ctr+=(sizeof(ushort)*8);
				for(int j = 1; j < m_nIters; j++, ctr+=(sizeof(ushort)*8)) {
					tmpval = rem(((rndbytes.Get<ushort>(ctr, sizeof(ushort)*8) << (sizeof(ushort) * 8)) | tmpval), m_nMod);
				}
				//cout << "tmpval = " << tmpval << ", ctr = " << ctr << ", m_nIters = " << m_nIters << endl;
				out.Set<int>(tmpval, (OTid * bitlength) + (i*m_nBitsMod), m_nBitsMod);
			}
		}
		else
		{
			out.SetBits(rndbytes.GetArr(), OTid*(m_nBitsMod*m_nNumElements), (m_nBitsMod*m_nNumElements));
		}
	}



private:
	CBitVector* m_vInput;
	int m_nNumElements;
	int m_nBitLength;
	int m_nMod;
	int m_nBitsMod;
	int m_nIters; //How many bits will be used to generate an element in Z_P
	BOOL m_bCompress;

};

#endif /* SHADEMASKING_H_ */
