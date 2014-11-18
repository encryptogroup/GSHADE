/*
 * asharov-lindell.h
 *
 *  Created on: Mar 20, 2013
 *      Author: mzohner
 */

#ifndef ASHAROVLINDELL_H_
#define ASHAROVLINDELL_H_


#include "baseOT.h"

class AsharovLindell : public BaseOT
{
	number m_Div;

	public:
	AsharovLindell(){};
	~AsharovLindell(){};

	AsharovLindell(SECLVL sec, BYTE* seed)
	{
		Init(sec, seed);
#ifdef OTEXT_USE_GMP
		mpz_t tmp;
		mpz_init(tmp);
		mpz_sub_ui(tmp, m_fParams.ifcparams.p, 1);
		mpz_cdiv_q(m_Div, tmp, m_fParams.ifcparams.q);
#endif
	};

	// Sender and receiver method using Miracl
	BOOL Receiver(int nSndVals, int nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	BOOL Sender(int nSndVals, int nOTs, CSocket& sock, BYTE* ret);





};

#endif /* ASHAROVLINDELL_H_ */
