#include "asharov-lindell.h"

BOOL AsharovLindell::Receiver(int nSndVals, int nOTs, CBitVector& choices, CSocket& socket, BYTE* ret)
{
	int nBufSize = nSndVals * m_fParams.elebytelen * nOTs;

	fieldelement g, h0, h1, h[nOTs], u, pDec;
	number beta[nOTs];
	brickexp bg, bu;

	//stores the answer bits of the receiver (d) in the Naor Pinkas Protocol
	BYTE* pBuf = new BYTE[nBufSize];

	FieldElementInit(h0);
	FieldElementInit(h1);
	FieldElementInit(pDec);
	FieldElementInit(u);
	FieldElementInit(g);

	FieldGetGenerator(g, m_fParams);

	BrickInit(&bg, g, m_fParams);


	for (int i = 0, idx = 0; i < nOTs; i++) {
		FieldElementInit(h[i]);
		FieldElementInit(beta[i]);
		FieldSampleRandomGenerator(h[i], m_Div, m_fParams);
		GetRandomNumber(beta[i], m_fParams.secparam, m_fParams);
	}

	BYTE* pBufIdx = pBuf;

	//now, compute hi0, hi1 according to \sigma_i (m_r[i])
	for (int i = 0, idx = 0; i < nOTs; i++) {
		if (!choices.GetBit(i))
		{
			BrickPowerMod(&bg, h0, beta[i]);
			FieldElementSet(h1, h[i]);
		}
		else
		{
			FieldElementSet(h0, h[i]);
			BrickPowerMod(&bg, h1, beta[i]);
		}

		// put hi0, hi1
		FieldElementToByte(pBufIdx, m_fParams.elebytelen, h0);
		pBufIdx += m_fParams.elebytelen;
		FieldElementToByte(pBufIdx, m_fParams.elebytelen, h1);
		pBufIdx += m_fParams.elebytelen;
	}

	socket.Send(pBuf, nBufSize);
	delete[] pBuf;

	////////////////////////////////////////////////////////////////////////////
	// OT Step 2:
	// Recieve u, (v_i0,v_i1) for every i=1,...,m_nNumberOfInitialOT
	// For every i, compute ki = u^alphai and then xi^\sigma = vi^\sigma XOR KDF(ki^\sigma)
	////////////////////////////////////////////////////////////////////////////

	nBufSize = m_fParams.elebytelen;
	pBuf = new BYTE[nBufSize];
	socket.Receive(pBuf, nBufSize);

	//reading u
	ByteToFieldElement(&u, m_fParams.elebytelen, pBuf);

	BrickInit(&bu, u, m_fParams);

	BYTE* retPtr = ret;
	for (int k = 0; k < nOTs; k++)
	{
		BrickPowerMod(&bu, pDec, beta[k]);
		FieldElementToByte(pBuf, m_fParams.elebytelen, pDec);
		hashReturn(retPtr, pBuf, m_fParams.elebytelen, k);
		retPtr += SHA1_BYTES;
	}

	BrickDelete(&bu);
	BrickDelete(&bg);

	return true;
}


BOOL AsharovLindell::Sender(int nSndVals, int nOTs, CSocket& socket, BYTE* ret)
{
	int nBufSize = m_fParams.elebytelen;

	fieldelement u, g, pH, pK;
	number alpha;

	BYTE* pBuf = new BYTE[nBufSize];

	FieldElementInit(pH);
	FieldElementInit(pK);
	FieldElementInit(alpha);
	FieldElementInit(u);
	FieldElementInit(g);

	FieldGetGenerator(g, m_fParams);

	//random u
	GetRandomNumber(alpha, m_fParams.secparam, m_fParams);
	FieldElementPow(u, g, alpha, m_fParams);

	FieldElementToByte(pBuf, m_fParams.elebytelen, u);
	socket.Send(pBuf, nBufSize);

	//====================================================
	// N-P sender: receive pk0
	delete pBuf;

	nBufSize = m_fParams.elebytelen * nOTs * nSndVals;
	pBuf = new BYTE[nBufSize];
	socket.Receive(pBuf, nBufSize);


	BYTE* pBufIdx = pBuf;
	BYTE* retPtr = ret;

	for(int k = 0; k < nSndVals * nOTs; k++)
	{
		ByteToFieldElement(&pH, m_fParams.elebytelen, pBufIdx);
		FieldElementPow(pK, pH, alpha, m_fParams);
		FieldElementToByte(pBufIdx, m_fParams.elebytelen, pK);

		hashReturn(retPtr, pBufIdx, m_fParams.elebytelen, k/nSndVals);
		pBufIdx += m_fParams.elebytelen;
		retPtr += SHA1_BYTES;
	}

	return true;
}




