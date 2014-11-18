#include "naor-pinkas.h"



BOOL NaorPinkas::Receiver(int nSndVals, int nOTs, CBitVector& choices,
		CSocket& socket, BYTE* ret) {

	fieldelement PK_sigma[nOTs], PK0, pDec[nOTs], pC[nSndVals], g;
	number pK[nOTs];

	brickexp bg, bc;

	FieldElementInit(g);
	FieldGetGenerator(g, m_fParams);
	BrickInit(&bg, g, m_fParams);

	BYTE* pBuf = new BYTE[nOTs * m_fParams.elebytelen];
	int nBufSize = nSndVals * m_fParams.elebytelen;

	FieldElementInit(PK0);

	//calculate the generator of the group
	for (int k = 0; k < nOTs; k++)
	{
		FieldElementInit(PK_sigma[k]);
		FieldElementInit(pK[k]);

		GetRandomNumber(pK[k], m_fParams.secparam, m_fParams);
		BrickPowerMod(&bg, PK_sigma[k], pK[k]);
	}

	socket.Receive(pBuf, nBufSize);
	BYTE* pBufIdx = pBuf;

	for (int u = 0; u < nSndVals; u++) {
		FieldElementInit(pC[u]);
		ByteToFieldElement(pC + u, m_fParams.elebytelen, pBufIdx);
		pBufIdx += m_fParams.elebytelen;
	}

	BrickInit(&bc, pC[0], m_fParams);

	//====================================================
	// N-P receiver: send pk0
	pBufIdx = pBuf;
	int choice;
	for (int k = 0; k < nOTs; k++)
	{
		choice = choices.GetBit(k);
		if (choice != 0) {
			FieldElementDiv(PK0, pC[choice], PK_sigma[k], m_fParams);//PK0 = pC[choice];
		} else {
			FieldElementSet(PK0, PK_sigma[k]);//PK0 = PK_sigma[k];
		}
		//cout << "PK0: " << PK0 << ", PK_sigma: " << PK_sigma[k] << ", choice: " << choice << ", pC[choice: " << pC[choice] << endl;
		FieldElementToByte(pBufIdx, m_fParams.elebytelen, PK0);
		pBufIdx += m_fParams.elebytelen;
	}

	socket.Send(pBuf, nOTs * m_fParams.elebytelen);

	delete [] pBuf;
	pBuf = new BYTE[m_fParams.elebytelen];
	BYTE* retPtr = ret;

	for (int k = 0; k < nOTs; k++) {
		FieldElementInit(pDec[k]);
		BrickPowerMod(&bc, pDec[k], pK[k]);
		FieldElementToByte(pBuf, m_fParams.elebytelen, pDec[k]);

		hashReturn(retPtr, pBuf, m_fParams.elebytelen, k);
		retPtr += SHA1_BYTES;
	}

	BrickDelete(&bc);
	BrickDelete(&bg);

	delete [] pBuf;

	return true;
}




BOOL NaorPinkas::Sender(int nSndVals, int nOTs, CSocket& socket, BYTE* ret)
{
	number alpha, PKr, tmp;

	fieldelement pCr[nSndVals], pC[nSndVals], fetmp, PK0r, g;

	BYTE* pBuf = new BYTE[m_fParams.elebytelen * nOTs];

	FieldElementInit(g);
	FieldGetGenerator(g, m_fParams);

	FieldElementInit(alpha);
	FieldElementInit(fetmp);
	FieldElementInit(pC[0]);
	FieldElementInit(PK0r);
	FieldElementInit(tmp);

	//random C1
	GetRandomNumber(alpha, m_fParams.secparam, m_fParams);//alpha = rand(m_nSecParam, 2);
	FieldElementPow(pC[0], g, alpha, m_fParams);

	//random C(i+1)
	for (int u = 1; u < nSndVals; u++) {
		FieldElementInit(pC[u]);
		GetRandomNumber(tmp, m_fParams.secparam, m_fParams);//alpha = rand(m_nSecParam, 2);
		FieldElementPow(pC[u], g, tmp, m_fParams);
	}

	//====================================================
	// Export the generated C_1-C_nSndVals to a BYTE vector and send them to the receiver
	int nBufSize = nSndVals * m_fParams.elebytelen;
	BYTE* pBufIdx = pBuf;
	for (int u = 0; u < nSndVals; u++) {
		FieldElementToByte(pBufIdx, m_fParams.elebytelen, pC[u]);
		pBufIdx += m_fParams.elebytelen;
	}
	socket.Send(pBuf, nBufSize);

	//====================================================
	// compute C^R
	for (int u = 1; u < nSndVals; u++) {
		FieldElementInit(pCr[u]);
		FieldElementPow(pCr[u], pC[u], alpha, m_fParams);
	}
	//====================================================
	// N-P sender: receive pk0
	nBufSize = m_fParams.elebytelen * nOTs;
	socket.Receive(pBuf, nBufSize);

	pBufIdx = pBuf;
	fieldelement pPK0[nOTs];

	for (int k = 0; k < nOTs; k++) {
		FieldElementInit(pPK0[k]);
		ByteToFieldElement(pPK0 + k, m_fParams.elebytelen, pBufIdx);
		pBufIdx += m_fParams.elebytelen;
	}

	//====================================================
	// Write all nOTs * nSndVals possible values to ret
	delete [] pBuf;
	pBuf = new BYTE[m_fParams.elebytelen * nSndVals];
	BYTE* retPtr = ret;
	for (int k = 0; k < nOTs; k++)
	{
		pBufIdx = pBuf;
		for (int u = 0; u < nSndVals; u++) {

			if (u == 0) {
				// pk0^r
				FieldElementPow(PK0r, pPK0[k], alpha, m_fParams);
				FieldElementToByte(pBufIdx, m_fParams.elebytelen, PK0r);

			} else {
				// pk^r
				FieldElementDiv(fetmp, pCr[u], PK0r, m_fParams);
				FieldElementToByte(pBufIdx, m_fParams.elebytelen, fetmp);
			}
			hashReturn(retPtr, pBufIdx, m_fParams.elebytelen, k);
			pBufIdx += m_fParams.elebytelen;
			retPtr += SHA1_BYTES;
		}

	}

	delete [] pBuf;

	return true;
}
