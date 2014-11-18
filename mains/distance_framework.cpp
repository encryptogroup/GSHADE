#include "distance_framework.h"

BOOL Init()
{
	// Random numbers

	HASH_CTX sha;
	MPC_HASH_INIT(&sha);
	MPC_HASH_UPDATE(&sha, (BYTE*) &m_nPID, sizeof(m_nPID));
	MPC_HASH_UPDATE(&sha, (BYTE*) m_nSeed, sizeof(m_nSeed));
	MPC_HASH_FINAL(&sha, m_aSeed);

	m_nCounter = 0;


	//TODO: Make security level choice dynamic
	bot = new NaorPinkas(m_sSecLvl, m_aSeed);

	m_vSockets.resize(m_nNumOTThreads);

	return TRUE;
}

BOOL Cleanup()
{
	for(int i = 0; i < m_nNumOTThreads; i++)
	{
		m_vSockets[i].Close();
	}
	return true;
}


BOOL Connect()
{
	BOOL bFail = FALSE;
	LONG lTO = CONNECT_TIMEO_MILISEC;

#ifndef BATCH
	cout << "Connecting to party "<< !m_nPID << ": " << m_nAddr << ", " << m_nPort << endl;
#endif
	for(int k = m_nNumOTThreads-1; k >= 0 ; k--)
	{
		for( int i=0; i<RETRY_CONNECT; i++ )
		{
			if( !m_vSockets[k].Socket() ) 
			{	
				printf("Socket failure: ");
				goto connect_failure; 
			}
			
			if( m_vSockets[k].Connect( m_nAddr, m_nPort, lTO))
			{
				// send pid when connected
				m_vSockets[k].Send( &k, sizeof(int) );
		#ifndef BATCH
				cout << " (" << !m_nPID << ") (" << k << ") connected" << endl;
		#endif
				if(k == 0) 
				{
					//cout << "connected" << endl;
					return TRUE;
				}
				else
				{
					break;
				}
				SleepMiliSec(10);
				m_vSockets[k].Close();
			}
			SleepMiliSec(20);
			if(i+1 == RETRY_CONNECT)
				goto server_not_available;
		}
	}
server_not_available:
	printf("Server not available: ");
connect_failure:
	cout << " (" << !m_nPID << ") connection failed" << endl;
	return FALSE;
}



BOOL Listen()
{
#ifndef BATCH
	cout << "Listening: " << m_nAddr << ":" << m_nPort << endl;
#endif
	if( !m_vSockets[0].Socket() ) 
	{
		goto listen_failure;
	}
	if( !m_vSockets[0].Bind(m_nPort, m_nAddr) )
		goto listen_failure;
	if( !m_vSockets[0].Listen() )
		goto listen_failure;

	for( int i = 0; i<m_nNumOTThreads; i++ ) //twice the actual number, due to double sockets for OT
	{
		CSocket sock;
		//cout << "New round! " << endl;
		if( !m_vSockets[0].Accept(sock) )
		{
			cerr << "Error in accept" << endl;
			goto listen_failure;
		}
					
		UINT threadID;
		sock.Receive(&threadID, sizeof(int));

		if( threadID >= m_nNumOTThreads )
		{
			sock.Close();
			i--;
			continue;
		}

	#ifndef BATCH
		cout <<  " (" << m_nPID <<") (" << threadID << ") connection accepted" << endl;
	#endif
		// locate the socket appropriately
		m_vSockets[threadID].AttachFrom(sock);
		sock.Detach();
	}

#ifndef BATCH
	cout << "Listening finished"  << endl;
#endif
	return TRUE;

listen_failure:
	cout << "Listen failed" << endl;
	return FALSE;
}




void InitOTSender(const char* address, int port)
{
	int nSndVals = 2;
#ifdef OTTiming
	timeval np_begin, np_end;
#endif
	m_nPort = (USHORT) port;
	m_nAddr = address;
	//vKeySeeds = (AES_KEY*) malloc(sizeof(AES_KEY)*NUM_EXECS_NAOR_PINKAS);
	vKeySeeds = (BYTE*) malloc(AES_KEY_BYTES*NUM_EXECS_NAOR_PINKAS);
	//Initialize values
	Init();
	
	//Server listen
	Listen();
	
#ifdef OTTiming
	gettimeofday(&np_begin, NULL);
#endif	

	PrecomputeNaorPinkasSender();

#ifdef OTTiming
	gettimeofday(&np_end, NULL);
	printf("Time for performing the NP base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif	

	sender = new OTExtensionSender (nSndVals, NUM_EXECS_NAOR_PINKAS, m_vSockets.data(), U, vKeySeeds);
}

void InitOTReceiver(const char* address, int port)
{
	int nSndVals = 2;
	timeval np_begin, np_end;
	m_nPort = (USHORT) port;
	m_nAddr = address;
	//vKeySeedMtx = (AES_KEY*) malloc(sizeof(AES_KEY)*NUM_EXECS_NAOR_PINKAS * nSndVals);
	vKeySeedMtx = (BYTE*) malloc(AES_KEY_BYTES*NUM_EXECS_NAOR_PINKAS * nSndVals);
	//Initialize values
	Init();
	
	//Client connect
	Connect();
	
#ifdef OTTiming
	gettimeofday(&np_begin, NULL);
#endif

	PrecomputeNaorPinkasReceiver();
	
#ifdef OTTiming
	gettimeofday(&np_end, NULL);
	printf("Time for performing the NP base-OTs: %f seconds\n", getMillies(np_begin, np_end));
#endif	

	receiver = new OTExtensionReceiver(nSndVals, NUM_EXECS_NAOR_PINKAS, m_vSockets.data(), vKeySeedMtx, m_aSeed);
}

BOOL PrecomputeNaorPinkasSender()
{

	int nSndVals = 2;
	BYTE* pBuf = new BYTE[NUM_EXECS_NAOR_PINKAS * SHA1_BYTES]; 
	int log_nVals = (int) ceil(log(nSndVals)/log(2)), cnt = 0;
	
	U.Create(NUM_EXECS_NAOR_PINKAS*log_nVals, m_aSeed, cnt);
	
	bot->Receiver(nSndVals, NUM_EXECS_NAOR_PINKAS, U, m_vSockets[0], pBuf);
	
	//Key expansion
	BYTE* pBufIdx = pBuf;
	for(int i=0; i<NUM_EXECS_NAOR_PINKAS; i++ ) //80 HF calls for the Naor Pinkas protocol
	{
		memcpy(vKeySeeds + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
		pBufIdx+=SHA1_BYTES;
	} 
 	delete [] pBuf;	

 	return true;
}

BOOL PrecomputeNaorPinkasReceiver()
{
	int nSndVals = 2;
	
	// Execute NP receiver routine and obtain the key 
	BYTE* pBuf = new BYTE[SHA1_BYTES * NUM_EXECS_NAOR_PINKAS * nSndVals];

	//=================================================	
	// N-P sender: send: C0 (=g^r), C1, C2, C3 
	bot->Sender(nSndVals, NUM_EXECS_NAOR_PINKAS, m_vSockets[0], pBuf);
	
	//Key expansion
	BYTE* pBufIdx = pBuf;
	for(int i=0; i<NUM_EXECS_NAOR_PINKAS * nSndVals; i++ )
	{
		memcpy(vKeySeedMtx + i * AES_KEY_BYTES, pBufIdx, AES_KEY_BYTES);
		pBufIdx += SHA1_BYTES;
	}
	
	delete [] pBuf;	

	return true;
}


BOOL ObliviouslySend(CBitVector& X1, CBitVector& X2, int numOTs, int bitlength)
{
	bool success = FALSE;
	int nSndVals = 2; //Perform 1-out-of-2 OT
#ifdef OTTiming
	timeval ot_begin, ot_end;
#endif

	
#ifdef OTTiming
	gettimeofday(&ot_begin, NULL);
#endif
	// Execute OT sender routine 	
	success = sender->send(numOTs, bitlength, X1, X2, C_OT, m_nNumOTThreads, m_fMaskFct);
	
#ifdef OTTiming
	gettimeofday(&ot_end, NULL);
	//printf("Time for performing OT extension: %f seconds\n", getMillies(ot_begin, ot_end)+ rndgentime);
	printf("%f\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif

	return success;
}

BOOL ObliviouslyReceive(CBitVector& choices, CBitVector& ret, int numOTs, int bitlength)
{
	bool success = FALSE;

#ifdef OTTiming
	timeval ot_begin, ot_end;
	gettimeofday(&ot_begin, NULL);
#endif
	
	success = receiver->receive(numOTs, bitlength, choices, ret, C_OT, m_nNumOTThreads, m_fMaskFct);
	
	
#ifdef OTTiming
	gettimeofday(&ot_end, NULL);
	//printf("Time for performing OT extension: %f seconds\n", getMillies(ot_begin, ot_end) + rndgentime);
	printf("%f\n", getMillies(ot_begin, ot_end) + rndgentime);
#endif
	
	return success;
}

/*
 * 1) choose which distance to compute
 * 2) choose the element bit lengths
 * 3) perform OTs
 * 4) evaluate GMW/Yao
 */

int main(int argc, char** argv)
{
	const char* addr = "127.0.0.1";
	int port = 7766;
	int runs = 1;

	timeval tempStart, tempEnd;

	m_sSecLvl = ST;

	m_nNumOTThreads = 1;


	if(argc != 2)
	{
		cout<< "Please call with 0 if acting as server or 1 if acting as client" << endl;
		return 0;
	}
	m_nPID = atoi(argv[1]);

	cout << "Playing as role: " << m_nPID << endl;
	if(m_nPID == IDSERVER) { //Play as OT sender
		m_nSeed = m_nSeedA;
		InitOTSender(addr, port);
	} else {//Play as OT receiver
		m_nSeed = m_nSeedB;
		InitOTReceiver(addr, port);
	}

	testRoutine();

	/* Benchmark Eigenface computation*/
	int Kdash = 10304;
	int bitlen = 8;
	int K = 12;
	int dbsize = 1000;
	gettimeofday(&tempStart, NULL);
	for(int i = 0; i < runs; i++)
		testEigenfaces(Kdash, bitlen, K, dbsize);
	gettimeofday(&tempEnd, NULL);
	cout << "Required time for computing the Eigenfaces of a " << Kdash << " pixel image with " << bitlen << "-bit pixels and a "<<
			dbsize << "-element database: " << getMillies(tempStart, tempEnd)/runs << "s" << endl;
	/* End of Eigenface computation*/

	/* Benchmark Eigenface computation*/
	bitlen = 8;
	K = 12;
	dbsize = 1000;
	gettimeofday(&tempStart, NULL);
	for(int i = 0; i < runs; i++)
		testEuclideanDistance(K, bitlen, dbsize);
	gettimeofday(&tempEnd, NULL);
	cout << "Required time for computing the " << K << "-dimensional 1-vs-" << dbsize << " Euclidean Distance with " << bitlen
			<< "-bit coordinates: " << getMillies(tempStart, tempEnd)/runs << "s" << endl;
	/* End of Eigenface computation*/


	/* Benchmark Hamming distance computation*/
	dbsize = 50000;
	int idxlen = 900;
	gettimeofday(&tempStart, NULL);
	for(int i = 0; i < runs; i++)
		testHammingDistance(idxlen, dbsize);
	gettimeofday(&tempEnd, NULL);

	cout << "Required time for computing the 1-vs-" << dbsize << " Hamming distance on " << idxlen << "-bit elements: "
			<< getMillies(tempStart, tempEnd)/runs << "s" << endl;
	/* End of Hamming distance computation*/

	Cleanup();

	return 1;
}

void testEigenfaces(int Kdash, int bitlen, int K, int dbsize) {
	int projbitlen = 2*bitlen + CEIL_LOG2(Kdash);
	int eigenbitlen = 50;//2*projbitlen+1;
	int distbitlen = 50;//eigenbitlen + CEIL_LOG2(K);
	uint64_t mask = (1<<projbitlen)-1, tmp, tmpsum;
	CBitVector clientimage, U, serverdb, projshares,
	eigenshares, distanceshares, output;


	//consists of Kdash x bitlen-bit elements
	clientimage.Create(Kdash, bitlen);
	//the projection matrix
	U.Create(Kdash, K, bitlen);
	//dbsize vectors with K elements of bitlen*2+CEIL_LOG2(K)-bit length
	serverdb.Create(K, dbsize, projbitlen);
	//stores the temporary shares from the projection
	projshares.Create(K, projbitlen);
	//stores the shares of the eigenfaces
	eigenshares.Create(K, dbsize, eigenbitlen);
	//shares of the resulting Euclidean distances
	distanceshares.Create(dbsize, distbitlen);
	//the protocol output
	output.Create(dbsize, distbitlen);


	for(int i = 0; i < Kdash; i++) {
		clientimage.Set<int>(i+15, i);
		//cout << "ci[" << i << "] = " << clientimage.Get<int>(i) << endl;
	}

	for(int i = 0; i < dbsize; i++) {
		for(int j = 0; j < K; j++) {
			serverdb.Set2D<int>(i*K+j+15, i, j);
			//cout << "sdb[" << i << "][" << j << "]= " << serverdb.Get2D<int>(i,j) << endl;
		}
	}

	for(int i = 0; i < Kdash; i++) {
		for(int j = 0; j < K; j++) {
			U.Set2D<int>(i*K + j+15, i, j);
			//cout << "U[" << i << "][" << j << "]= " << U.Get2D<int>(i,j) << endl;
		}
	}

	if(m_nPID == IDSERVER) {
		ComputeSP(U, projshares, Kdash, K, bitlen);
	} else {
		ComputeSP(clientimage, projshares, Kdash, K, bitlen);
	}

	/* Verify projection output */
	/*CBitVector testout;
	testout.Create(K, projbitlen);
	ReconstructOutput(projshares, testout, K, projbitlen);

	if(m_nPID != IDSERVER) {
		CBitVector verifyout;
		verifyout.Create(K, projbitlen);

		for(int i = 0; i < K; i++) {
			tmp = 0;
			for(int j = 0; j < Kdash; j++) {
				tmp = tmp + (clientimage.Get<uint64_t>(j) * U.Get2D<uint64_t>(j,i));
				//cout << i << ", " << j << ": " << tmp << endl;
			}
			verifyout.Set<uint64_t>(tmp, i);
		}

		for(int i = 0; i < K; i++)
			cout << i << "-th proj = " << testout.Get<uint64_t>(i) << " vs. " << verifyout.Get<uint64_t>(i) << endl;
	}*/
	/* End of verify projection output */


	if(m_nPID == IDSERVER) {
		for(int i = 0; i < K; i++) {
			tmp = projshares.Get<uint64_t>(i);
			for(int j = 0; j < dbsize; j++) {
				tmpsum = (tmp + serverdb.Get2D<uint64_t>(i,j)) & mask;
				serverdb.Set2D<uint64_t>(tmpsum, i, j);
			}
		}
		ComputeED(serverdb, eigenshares, K, dbsize, projbitlen);
	} else {
		ComputeED(projshares, eigenshares, K, dbsize, projbitlen);
	}

	for(int i = 0; i < dbsize; i++) {
		tmpsum = 0;
		for(int j = 0; j < K; j++) {
			tmpsum += eigenshares.Get2D<uint64_t>(j,i);
		}
		distanceshares.Set<uint64_t>(tmpsum, i);
	}

	ReconstructOutput(distanceshares, output, dbsize, distbitlen);

	clientimage.delCBitVector();
	U.delCBitVector();
	serverdb.delCBitVector();
	projshares.delCBitVector();
	eigenshares.delCBitVector();
	distanceshares.delCBitVector();
	output.delCBitVector();
}


void testEuclideanDistance(int K, int bitlen, int dbsize) {
	int eigenbitlen = 2*bitlen;
	int distbitlen = eigenbitlen + CEIL_LOG2(K);
	uint64_t tmpsum;

	CBitVector clientimage, serverdb, eigenshares, distanceshares, output;

	//consists of Kdash x bitlen-bit elements
	clientimage.Create(K, bitlen);
	//dbsize vectors with K elements of bitlen*2+CEIL_LOG2(K)-bit length
	serverdb.Create(K, dbsize, bitlen);
	eigenshares.Create(K, dbsize, eigenbitlen);
	//shares of the resulting Euclidean distances
	distanceshares.Create(dbsize, distbitlen);
	//the protocol output
	output.Create(dbsize, distbitlen);


	for(int i = 0; i < K; i++) {
		clientimage.Set<int>(i+15, i);
		//cout << "ci[" << i << "] = " << clientimage.Get<int>(i) << endl;
	}

	for(int i = 0; i < dbsize; i++) {
		for(int j = 0; j < K; j++) {
			serverdb.Set2D<int>(i*K+j+15, i, j);
			//cout << "sdb[" << i << "][" << j << "]= " << serverdb.Get2D<int>(i,j) << endl;
		}
	}


	if(m_nPID == IDSERVER) {
		ComputeED(serverdb, eigenshares, K, dbsize, bitlen);
	} else {
		ComputeED(clientimage, eigenshares, K, dbsize, bitlen);
	}

	for(int i = 0; i < dbsize; i++) {
		tmpsum = 0;
		for(int j = 0; j < K; j++) {
			tmpsum += eigenshares.Get2D<uint64_t>(j,i);
		}
		distanceshares.Set<uint64_t>(tmpsum, i);
	}

	ReconstructOutput(distanceshares, output, dbsize, distbitlen);

	clientimage.delCBitVector();
	serverdb.delCBitVector();
	eigenshares.delCBitVector();
	distanceshares.delCBitVector();
	output.delCBitVector();
}


void testHammingDistance(int idxlen, int dbsize) {
	int bitlen = CEIL_LOG2(idxlen);

	if(m_nPID == IDSERVER) {
		CBitVector serverdb, dummyout;
		serverdb.Create(dbsize, bitlen, m_aSeed, m_nCounter);
		ComputeHD(serverdb, dummyout, idxlen, dbsize, 1<<bitlen);
		//serverdb.Print(0,idxlen);


	} else {
		CBitVector clientimage, output;
		clientimage.Create(bitlen, m_aSeed, m_nCounter);
		output.Create(dbsize, bitlen);
		ComputeHD(clientimage, output, idxlen, dbsize, 1<<bitlen);
		//clientimage.Print(0,idxlen);
	}
}





/*
 * Securely compute the scalar product
 * dimvec = K'
 * dimproj = K
 * inbitlen = size of x and u
 */
void ComputeSP(CBitVector& input, CBitVector& output, int Kdash, int K, int inbitlen) {
	int prodbitlen = inbitlen * 2+CEIL_LOG2(K);

	CBitVector products;
	products.Create(Kdash, K, inbitlen*2);
	ComputeMult(input, products, Kdash, K, inbitlen, prodbitlen);

	//sum up products to obtain scalar product
	uint64_t tmp;
	for(int i = 0; i < K; i++) {
		tmp = 0;
		for(int j = 0; j < Kdash; j++) {
			tmp += products.Get2D<uint64_t>(j,i);
		}
		//cout << i << "-th share: " << tmp;
		output.Set<uint64_t>(tmp,i);
		//cout << " (" << output.Get<uint64_t>(i) << ")" << endl;
	}
	products.delCBitVector();
}


/*
 * input: two-dimensional CBitVector for the server and one-dimensional vector for the client
 */
void ComputeED(CBitVector& input, CBitVector& output, int numvals, int dbsize, int inbitlen) {
	int numelements = m_nPID == IDSERVER ? numvals * dbsize : numvals;
	int dstbitlen = 2*inbitlen;
	int outbitlen = 2*inbitlen+1;
	CBitVector squarein, mixprod, dmixprod;
	squarein.Create(numelements, dstbitlen);
	mixprod.Create(numvals, dbsize, dstbitlen);
	dmixprod.Create(numvals, dbsize, outbitlen);


	squarein.Reset();
	mixprod.Reset();
	dmixprod.Reset();

	ComputeSquare(input, squarein, numelements);
	/*cout << "Input: ";
	input.PrintHex();
	cout << "Squared input: ";
	squarein.PrintHex();*/
	ComputeMult(input, mixprod, numvals, dbsize, inbitlen, dstbitlen);

	/* Reconstruct output to test its correctness */
	/*CBitVector testout;
	testout.Create(numvals, dbsize, inbitlen*2);
	ReconstructOutput(mixprod, testout, numvals * dbsize, dstbitlen);

	if(m_nPID != IDSERVER) {
		for(int i = 0; i < dbsize * numvals; i++) {
			cout << "Test product i = " << i << ": " << testout.Get<uint64_t>(i) << endl;
		}
	}*/
	//end of test

	ComputeDouble(mixprod, dmixprod, numvals * dbsize);

	uint64_t res, pow2, dmix, groupmod = 1<<(outbitlen);
	//sum up all shares
	for(int i = 0; i < dbsize * numvals; i++) {
		if(m_nPID == IDSERVER)	{
			pow2 = squarein.Get<uint64_t>(i);
			dmix = dmixprod.Get<uint64_t>(i);
			res = sub(groupmod - dmix, pow2, groupmod); //TODO: might be problematic, test
		}
		else {
			pow2 = squarein.Get<uint64_t>(i/dbsize);
			dmix = dmixprod.Get<uint64_t>(i);
			res = sub(pow2, dmix, groupmod);//res = pow2 >= dmix ? pow2-dmix : groupmod - pow2 + dmix;
		}
		//cout << "squaretmp = " << pow2 << endl;
		//cout << "dmixedprod = " << dmixprod.Get<uint64_t>(i) << endl;
		//dmix = dmixprod.Get<uint64_t>(i);
		//cout << " res = " << res << endl;
		output.Set<uint64_t>(res, i);
	}
	squarein.delCBitVector();
	mixprod.delCBitVector();
	dmixprod.delCBitVector();
}

void ComputeSquare(CBitVector& input, CBitVector& output, int numelements) {
	uint64_t val, res;
	for(int i = 0; i < numelements; i++) {
		val = input.Get<uint64_t>(i);
		res = val * val;
		output.Set<uint64_t>(res, i);
		//cout << "square: " << res << " vs. " << output.Get<uint64_t>(i) << endl;
	}
}

void ComputeDouble(CBitVector& input, CBitVector& output, int numelements) {
	uint64_t val;
	for(int i = 0; i < numelements; i++) {
		val = 2* input.Get<uint64_t>(i);
		output.Set<uint64_t>(val, i);
	}
}

void ComputeMult(CBitVector& input, CBitVector& output, int numvals, int dbsize, int inbitlen, int outbitlen) {
	int numOTs = numvals * inbitlen;
	//Pre-set output to 0 since it is used for summation later on
	//input.PrintHex();
	output.Reset();
	if(m_nPID == IDSERVER) {
		//First compute the projection into the feature space
		CBitVector masks, cormasks;
		masks.Create(numOTs, dbsize, outbitlen);
		cormasks.Create(numOTs, dbsize, outbitlen);

		m_fMaskFct = new MulMasking(dbsize, inbitlen, outbitlen, &input);//new SHADEMasking(dbsize, bitlength, modulus);//

		cout << "Starting " << numOTs << " OTs on " << outbitlen * dbsize << " bit strings" << endl;
		ObliviouslySend(masks, cormasks, numOTs, outbitlen*dbsize);
		//cout << "Finished OT" << endl;

		//sum up masks and send back to receiver

		SumValuesMult(masks, output, outbitlen, numvals, inbitlen, dbsize);


		/*cout << "X0 = ";
		masks.PrintHex();
		cout << "X1 = ";
		cormasks.PrintHex();
		cout << "Sum = ";
		output.PrintHex();
		uint64_t diff;
		for(int i = 0; i < dbsize; i++) {
			cout << "Difference for i = " << i << " : ";
			for(int j = 0; j < numOTs; j++) 	{
				diff = cormasks.Get2D<uint64_t>(j,i) - masks.Get2D<uint64_t>(j,i);
				cout << diff << ", ";
			}
			cout << endl;
		}*/
		masks.delCBitVector();
		cormasks.delCBitVector();
	} else {//Act as receiver
		CBitVector otres;
		otres.Create(numOTs, dbsize, outbitlen);


		//cout << "size of result = " << numOTs * dbsize * elementlen << " bits" << endl;
		m_fMaskFct = new MulMasking(dbsize, inbitlen, outbitlen, &input);//new SHADEMasking(dbsize, bitlength, modulus);//

		cout << "Starting " << numOTs << " OTs on " << outbitlen * dbsize << " bit strings" << endl;
		ObliviouslyReceive(input, otres, numOTs, outbitlen*dbsize);
		/*cout << "Finished OT" << endl;
		cout << "C = ";
		input.PrintBinary();
		cout << "R = ";
		otres.PrintHex();*/

		//sum up bit positions and obtain mask from sender
		SumValuesMult(otres, output, outbitlen, numvals, inbitlen, dbsize);

		//cout << "Sum = ";
		//output.PrintHex();
		otres.delCBitVector();
	}
}

void ReconstructOutput(CBitVector& input, CBitVector& output, int numelements, int bitlen)
{
	if(m_nPID == IDSERVER) {
		m_vSockets[0].Send(input.GetArr(), CEIL_DIVIDE(numelements * bitlen,8));

	} else {
		CBitVector rcvbuf;
		rcvbuf.Create(numelements, bitlen);
		m_vSockets[0].Receive(rcvbuf.GetArr(), CEIL_DIVIDE(numelements * bitlen,8));


		uint64_t tmp, rcved;
		uint64_t maxresval = 1<<bitlen;//(1<<resbitlen);
		for(int i = 0; i < numelements; i++) {
			//for(int j = 0; j < dbsize; j++) {
				//compute tmp - rcved
				tmp = input.Get<uint64_t>(i);
				rcved = rcvbuf.Get<uint64_t>(i);
				//cout << "i = " << i << ", tmp = " << (dec) << tmp << ", rcved = " << rcved << (dec) << " for " << bitlen << "-bit values"<< endl;
				tmp = sub(tmp, rcved, maxresval);//rcved > tmp ? tmp + maxresval - rcved: tmp- rcved;
				output.Set<int>(tmp, i);
			//}
		}
		rcvbuf.delCBitVector();
	}
}

void SumValuesMult(CBitVector& input, CBitVector& sum, int bitlen, int numvals, int dima, int dimb) {
	uint64_t mask = (1<<bitlen) -1;
	uint64_t tmp;
	for(int k = 0, inpos, outpos, shifts; k < numvals; k++) {
		for(int i = 0; i < dima; i++)	{
			inpos = i + k*dima;
			outpos = k;
			shifts = i;
			for(int j = 0; j < dimb; j++)	{
				tmp = input.Get2D<uint64_t>(inpos,j);
				tmp = (tmp << shifts) & mask;
				tmp = (tmp + sum.Get2D<uint64_t>(outpos, j)) & mask;
				sum.Set2D<uint64_t>(tmp, outpos, j);
			}
		}
	}
}


void ComputeHD(CBitVector& input, CBitVector& output, int numOTs, int dbsize, int modulus) {
	int elementlen = CEIL_LOG2(modulus);
	if(m_nPID == IDSERVER) 	{
		CBitVector masks, cormasks, gmasks;
		masks.Create(numOTs, dbsize, elementlen);
		cormasks.Create(numOTs, dbsize, elementlen);
		gmasks.Create(dbsize, elementlen);
		gmasks.Reset();

		m_fMaskFct = new SHADEMasking(dbsize, modulus, &input);//new SHADEMasking(dbsize, bitlength, modulus);//

		cout << "Starting " << numOTs << " OTs on " << elementlen * dbsize << " bit strings" << endl;
		ObliviouslySend(masks, cormasks, numOTs, elementlen*dbsize);

		//sum up masks and send back to receiver

		SumValuesHD(masks, gmasks, modulus, numOTs, dbsize);

		m_vSockets[0].Send(gmasks.GetArr(), CEIL_DIVIDE(dbsize * elementlen,8));

		masks.delCBitVector();
		cormasks.delCBitVector();
		gmasks.delCBitVector();
	} else {//Act as receiver
		CBitVector result;
		result.Create(numOTs, dbsize, elementlen);
		m_fMaskFct = new SHADEMasking(dbsize, modulus, &input);//new SHADEMasking(dbsize, bitlength, modulus);//

		cout << "Starting " << numOTs << " OTs on " << elementlen * dbsize << " bit strings" << endl;
		ObliviouslyReceive(input, result, numOTs, elementlen*dbsize);

		//sum up bit positions and obtain mask from sender
		CBitVector maskedres, masks;
		maskedres.Create(dbsize, elementlen);
		masks.Create(dbsize, elementlen);
		maskedres.Reset();
		SumValuesHD(result, maskedres, modulus, numOTs, dbsize);

		m_vSockets[0].Receive(masks.GetArr(), CEIL_DIVIDE(dbsize * elementlen,8));

		for(int i = 0, tmp; i < dbsize; i++)
		{
			tmp = maskedres.Get<int>(i);
			tmp = rem(tmp - masks.Get<int>(i), modulus);
			output.Set<int>(tmp, i);
		}

		maskedres.delCBitVector();
		masks.delCBitVector();
		result.delCBitVector();
 		/*for(int i = 0; i < dbsize; i++)
 		{
 			cout << "Hamming distance for i = " << i << " : " << output.Get<int>(i) << endl;
 		}*/

	}

}

void SumValuesHD(CBitVector& input, CBitVector& sum, int modulus, int dima, int dimb)
{
	for(int i = 0, tmp; i < dima; i++)
	{
		for(int j = 0; j < dimb; j++)
		{
			tmp = input.Get2D<int>(i,j);
			tmp = tmp + sum.Get<int>(j);
			if(tmp >= modulus)
				tmp-=modulus;
			sum.Set<int>(tmp, j);
		}
	}
}

void testRoutine()
{
	int modulus = 256;
	int bitlen = CEIL_LOG2(modulus);
	int dbsize = 4;
	int numOTs = modulus;
	int outbitlen = 2*bitlen+1;
	int vals[] = {5,7,13,18,22,23,42,45,255};
	int numvals = 4;

	int serverdb[dbsize];
	for(int i = 0; i < dbsize; i++)
		serverdb[i] = i+25;

	timeval tempStart, tempEnd;

	cout << "Playing as role: " << m_nPID << endl;
	if(m_nPID == IDSERVER) //Play as OT sender
	{
		CBitVector dbentries, shares, dummyvec;

		//Compute the Hamming distance
		dbentries.Create(numOTs, dbsize, bitlen, m_aSeed, m_nCounter);
		shares.Create(numvals, dbsize, outbitlen);

		gettimeofday(&tempStart, NULL);
		//ComputeHD(dbentries, dummyoutput, numOTs, dbsize, modulus);	//ObliviouslySend(masks, cormasks, numOTs, bitlength*dbsize);

 		gettimeofday(&tempEnd, NULL);
 		cout << "Required time for " << numOTs << " OTs and " << dbsize << " database " <<
 				bitlen << "-bit entries: " << getMillies(tempStart, tempEnd) << "s" << endl;


 		//Compute the Euclidean distance
 		numOTs = numvals * bitlen;
 		dbentries.Create(numvals, dbsize, bitlen, m_aSeed, m_nCounter);


 		for(int i = 0; i < numvals; i++) {
 			for(int j = 0; j < dbsize; j++) {
 				dbentries.Set2D<int>(serverdb[j], i, j);
 			}
 		}

		gettimeofday(&tempStart, NULL);
		//ComputeMult(dbentries, shares, numvals, dbsize, bitlength, resbitlen);	//ObliviouslySend(masks, cormasks, numOTs, bitlength*dbsize);
		ComputeED(dbentries, shares, numvals, dbsize, bitlen);

		//No output is obtained for the sender
		ReconstructOutput(shares, dummyvec, numvals * dbsize, outbitlen);

 		gettimeofday(&tempEnd, NULL);
 		cout << "Required time for computing the Euclidean distance between " << numvals << " elements and a " <<
 				dbsize << " element db with " << bitlen << " bit entries: " << getMillies(tempStart, tempEnd) << "s" << endl;


 		//Compute the scalar product
		gettimeofday(&tempStart, NULL);
		outbitlen = 2*bitlen + CEIL_LOG2(numvals);
		shares.Create(dbsize, outbitlen);

		ComputeSP(dbentries, shares, numvals, dbsize, bitlen);
		ReconstructOutput(shares, dummyvec, dbsize, outbitlen);

 		gettimeofday(&tempEnd, NULL);
 		cout << "Required time for computing the scalar product between " << numvals << " elements and a " <<
 				dbsize << " element db with " << bitlen << " bit entries: " << getMillies(tempStart, tempEnd) << "s" << endl;
	}
	else //Play as OT receiver
	{
		CBitVector choices, shares, distances;
		choices.Create(numOTs, m_aSeed, m_nCounter);


		distances.Create(numOTs, dbsize, bitlen);
		distances.Reset();

		gettimeofday(&tempStart, NULL);
		//ComputeHD(choices, response, numOTs, dbsize, modulus);
		//ObliviouslyReceive(choices, distances, numOTs, bitlength*dbsize);

 		gettimeofday(&tempEnd, NULL);
 		cout << "Required time for " << numOTs << " OTs and " << dbsize << " database " <<
 				bitlen << "-bit entries: " << getMillies(tempStart, tempEnd) << "s" << endl;

 		numOTs = numvals * bitlen;
 		choices.Create(numvals, bitlen);
 		distances.Create(numvals, dbsize, outbitlen);
 		shares.Create(numvals, dbsize, outbitlen);

 		for(int i = 0; i < numvals; i++)
 			choices.Set<int>(vals[i], i);

 		gettimeofday(&tempStart, NULL);
 		//ComputeMult(choices, shares, numvals, dbsize, bitlength, resbitlen);
 		ComputeED(choices, shares, numvals, dbsize, bitlen);

		ReconstructOutput(shares, distances, numvals * dbsize, outbitlen);

		for(int i = 0; i < numvals; i++) {
			for(int j = 0; j < dbsize; j++) {
				cout << "Euclidean distance for i = " << i << ", j = " << j << ": " << ", between " << vals[i] << ", and " 
					<< serverdb[j] << " = " << distances.Get2D<int>(i,j) << endl;
			}
		}

 		/*for(int i = 0; i < numvals; i++) {
 				for(int j = 0; j < dbsize; j++) 	{
 					if(distances.Get2D<int>(i,j) != ((vals[i] * j) & ((1<<bitlen)-1)))
 						cout << "Error at i = " << i << ", j = " << j << " with val = " << vals[i] <<
 						" and res = " << distances.Get2D<int>(i,j) << endl;
 				}
 		}*/
 		gettimeofday(&tempEnd, NULL);
 		cout << "Required time for computing the Euclidean distance between " << numvals << " elements and a " <<
 				dbsize << " element db with " << bitlen << " bit entries: " << getMillies(tempStart, tempEnd) << "s" << endl;


 		//Compute the scalar product
		gettimeofday(&tempStart, NULL);

		outbitlen = 2*bitlen + CEIL_LOG2(numvals); //the maximum size of the scalar product
		distances.Create(dbsize, outbitlen);
		shares.Create(dbsize, outbitlen);
		ComputeSP(choices, shares, numvals, dbsize, bitlen);


		ReconstructOutput(shares, distances, dbsize, outbitlen);
 		gettimeofday(&tempEnd, NULL);
 		cout << "Required time for computing the scalar product between " << numvals << " elements and a " <<
 				dbsize << " element db with " << bitlen << " bit entries: " << getMillies(tempStart, tempEnd) << "s" << endl;

 		for(int i = 0; i < dbsize; i++)
 		{
 			cout << i << "-th product: " << distances.Get<int>(i) << endl;
 		}

	}
}

