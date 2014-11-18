#include "naor-pinkas_noro.h"

BOOL NaorPinkasNoRO::Receiver(int nSndVals, int nOTs, CBitVector& choices, CSocket& socket, BYTE* ret)
{
	number a, b[nOTs], tmp;
	fieldelement g, x, y, w, z0, z1;
	brickexp bg, bx;

	FieldElementInit(z0);
	FieldElementInit(z1);
	FieldElementInit(tmp);
	FieldElementInit(y);
	FieldElementInit(w);
	FieldElementInit(g);

	FieldGetGenerator(g, m_fParams);

	BrickInit(&bg, g, m_fParams);


	//needs to store x
	int nBufSize = m_fParams.elebytelen;
	BYTE* pBuf = new BYTE[nBufSize];


	//Fix a and precompute g^a
	FieldElementInit(a);
	GetRandomNumber(a, m_fParams.secparam, m_fParams);

	FieldElementInit(x);
	BrickPowerMod(&bg, x, a);

	//export and send x
	FieldElementToByte(pBuf, m_fParams.elebytelen, x);
	socket.Send(pBuf, nBufSize);

	delete pBuf;
	nBufSize = 3*nOTs*m_fParams.elebytelen;
	pBuf = new BYTE[nBufSize];

	BrickInit(&bx, x, m_fParams);

	BYTE* pBufIdx = pBuf;

	for(int k = 0; k < nOTs; k++)
	{
		FieldElementInit(b[k]);

		//randomly sample b and compute y
		GetRandomNumber(b[k], m_fParams.secparam, m_fParams);
		BrickPowerMod(&bg, y, b[k]);

		//compute z0 and z1, depending on the choice bits
		GetRandomNumber(tmp, m_fParams.secparam, m_fParams);

		if(!choices.GetBit(k))
		{
			BrickPowerMod(&bx, z0, b[k]);
			BrickPowerMod(&bg, z1, tmp);
		}
		else
		{
			BrickPowerMod(&bg, z0, tmp);
			BrickPowerMod(&bx, z1, b[k]);
		}

		//export - first y, then z0, and lastly z1
		FieldElementToByte(pBufIdx, m_fParams.elebytelen, y);
		pBufIdx += m_fParams.elebytelen;
		FieldElementToByte(pBufIdx, m_fParams.elebytelen, z0);
		pBufIdx += m_fParams.elebytelen;
		FieldElementToByte(pBufIdx, m_fParams.elebytelen, z1);
		pBufIdx += m_fParams.elebytelen;

	}

	int nRecvBufSize = 2 * nOTs * m_fParams.elebytelen;
	BYTE* pRecvBuf = new BYTE[nRecvBufSize];
	socket.Receive(pRecvBuf, nRecvBufSize);
		
	socket.Send(pBuf, nBufSize);

	BYTE* retPtr = ret;
	pBufIdx = pRecvBuf;
	for(int k = 0; k < nOTs; k++)
	{
		//if the choice bit is zero take the first value, else the second
		ByteToFieldElement(&w, m_fParams.elebytelen, (pBufIdx+(choices.GetBit(k) * m_fParams.elebytelen)));

		//compute w_sigma^b
		FieldElementPow(w, w, b[k], m_fParams);

		//export result and hash
		FieldElementToByte(pBufIdx, m_fParams.elebytelen, w);
		hashReturn(retPtr, pBufIdx, m_fParams.elebytelen, k);

		retPtr += SHA1_BYTES;

		//Skip the next two values
		pBufIdx += 2*m_fParams.elebytelen;

	}
	BrickDelete(&bx);
	BrickDelete(&bg);
	return true;
}




BOOL NaorPinkasNoRO::Sender(int nSndVals, int nOTs, CSocket& socket, BYTE* ret)
{
	number s0[nOTs], s1[nOTs], r0[nOTs], r1[nOTs];
	fieldelement g, w0, w1, R0, R1, x, y, z0, z1, tmp;
	brickexp bg, bx;

	FieldElementInit(tmp);
	FieldElementInit(R0);
	FieldElementInit(R1);
	FieldElementInit(w0);
	FieldElementInit(w1);
	FieldElementInit(z0);
	FieldElementInit(z1);
	FieldElementInit(y);
	FieldElementInit(x);
	FieldElementInit(g);

	FieldGetGenerator(g, m_fParams);

	BrickInit(&bg, g, m_fParams);

	//needs to store x, nOTs*y, nOTs*z0, and nOTs*z1
	int nBufSize = m_fParams.elebytelen;
	BYTE* pBuf = new BYTE[nBufSize];

	socket.Receive(pBuf, nBufSize);

	//import x and compute fixed Point Exponentiation of x
	ByteToFieldElement(&x, m_fParams.elebytelen, pBuf);

	BrickInit(&bx, x, m_fParams);

	delete pBuf;
	nBufSize = 2*nOTs * (m_fParams.elebytelen);
	pBuf = new BYTE[nBufSize];

	BYTE* pBufIdx = pBuf;	
	for(int k = 0; k < nOTs; k++)
	{
		FieldElementInit(s0[k]);
		FieldElementInit(s1[k]);
		FieldElementInit(r0[k]);
		FieldElementInit(r1[k]);

		GetRandomNumber(s0[k], m_fParams.secparam, m_fParams);
		GetRandomNumber(s1[k], m_fParams.secparam, m_fParams);
		GetRandomNumber(r0[k], m_fParams.secparam, m_fParams);
		GetRandomNumber(r1[k], m_fParams.secparam, m_fParams);
		
		//compute w0 and export it		
		BrickPowerMod(&bx, tmp, s0[k]);
		BrickPowerMod(&bg, R0, r0[k]);
		FieldElementMul(w0, tmp, R0, m_fParams);

		FieldElementToByte(pBufIdx, m_fParams.elebytelen, w0);
		pBufIdx += m_fParams.elebytelen;
				
		//compute w1 and export it		
		BrickPowerMod(&bx, tmp, s1[k]);
		BrickPowerMod(&bg, R1, r1[k]);
		FieldElementMul(w1, tmp, R1, m_fParams);

		FieldElementToByte(pBufIdx, m_fParams.elebytelen, w1);
		pBufIdx += m_fParams.elebytelen;
	}
	
	//Send data off
	socket.Send(pBuf, nBufSize);
	
	delete pBuf;
	nBufSize = 3*nOTs * (m_fParams.elebytelen);
	pBuf = new BYTE[nBufSize];
	
	//Receive new data
	socket.Receive(pBuf, nBufSize);
	
	BYTE* retPtr = ret;
	pBufIdx = pBuf;
	for(int k = 0; k < nOTs; k++)
	{
		//get y, z0, and z1
		ByteToFieldElement(&y, m_fParams.elebytelen, pBufIdx);
		pBufIdx += m_fParams.elebytelen;
		ByteToFieldElement(&z0, m_fParams.elebytelen, pBufIdx);
		pBufIdx += m_fParams.elebytelen;
		ByteToFieldElement(&z1, m_fParams.elebytelen, pBufIdx);
		pBufIdx += m_fParams.elebytelen;
		
		//compute first possible hash 
		FieldElementDoublePowMul(tmp, y, r0[k], z0, s0[k], m_fParams);

		//export result and hash
		FieldElementToByte(pBuf, m_fParams.elebytelen, tmp);
		hashReturn(retPtr, pBuf, (m_fParams.elebytelen), k);
		retPtr += SHA1_BYTES;

		//compute second possible hash 
		FieldElementDoublePowMul(tmp, y, r1[k], z1, s1[k], m_fParams);

		//export result and hash
		FieldElementToByte(pBuf, m_fParams.elebytelen, tmp);
		hashReturn(retPtr, pBuf, m_fParams.elebytelen, k);
		retPtr += SHA1_BYTES;
	}

	BrickDelete(&bx);
	BrickDelete(&bg);

	return true;
}

