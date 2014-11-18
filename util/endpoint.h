//endpoint.h
#ifndef __ENDPOINT_H__BY_SGCHOI
#define __ENDPOINT_H__BY_SGCHOI

#include "thread.h"
#include "socket.h"

class CMsg
{
public:
	CMsg(){ m_nRef = 1;}
	virtual ~CMsg(){}
public:
	UINT AddRef(){ return ++m_nRef; }
	void Release(){ if(--m_nRef == 0) delete this;}

private:
	UINT m_nRef;
};

class COneSockEndpoint 
{
public:
	COneSockEndpoint(){m_bStop = FALSE;}
	virtual ~COneSockEndpoint(){}

public:
	BOOL ConnectRun(const string& ip, USHORT port)
	{
		if(!m_sock.Socket()) return FALSE;
		if(!m_sock.Bind()) return FALSE;
		if(!m_sock.Connect(ip, port)) return FALSE;

		return Run();
	}

	BOOL ListenRun(USHORT port)
	{
		CSocket sock;
		if(!sock.Socket()) return FALSE;
		if(!sock.Bind(port)) return FALSE;
		if(!sock.Listen()) return FALSE;
		if(!sock.Accept(m_sock)) return FALSE;

		sock.Close();

		return Run();
	}

	virtual void OnInitialConnect() = 0;
	virtual void OnReceiveMsg(CMsg* ) = 0;
	virtual BOOL SendMsg(CMsg* ) = 0;
	virtual CMsg* RecvMsg() = 0;
	void Stop(){ m_bStop = TRUE; }

private:
	BOOL Run()
	{
		OnInitialConnect();

		while(!m_bStop)
		{
			CMsg* pMsg = RecvMsg();
			if( !pMsg ) break;
			OnReceiveMsg(pMsg);
			pMsg->Release();
		}

		m_sock.Close();
		return TRUE;
	}

protected: 
	CSocket m_sock;
	BOOL	m_bStop;
};

class CMultiSockEndpoint 
{
public:
	CMultiSockEndpoint(){GetInstance(this); m_bStop = FALSE;}
	virtual ~CMultiSockEndpoint(){}

public:
	static CMultiSockEndpoint* GetInstance(CMultiSockEndpoint* p = NULL)
	{
		static CMultiSockEndpoint*	s_p;
		if( p ) s_p = p;
		return s_p;
	}


	virtual void OnInitialConnect(int id) = 0;
	virtual void OnReceiveMsg(int id, CMsg* ) = 0;
	virtual BOOL  SendMsg(int id, CMsg* ) = 0;
	virtual CMsg* RecvMsg(int id) = 0;

public:
	void Stop(){ m_bStop = TRUE; }

	BOOL ConnectRun(const vector< pair<string, USHORT> >& vAddrs)
	{
		m_vThreads.resize(vAddrs.size());

		BOOL bError = FALSE; 
		for(UINT i=0; i<vAddrs.size(); i++ )
		{
			m_vThreads.push_back(new CRecvThread());
			m_vThreads[i]->m_nID = i;
			if(!m_vThreads[i]->m_sock.Socket()) bError = TRUE; 
			if(!m_vThreads[i]->m_sock.Bind()) bError = TRUE;
			if(!m_vThreads[i]->m_sock.Connect(vAddrs[i].first, vAddrs[i].second)) bError = TRUE;

			if( bError ) break;
		}

		if( bError )
		{
			for(UINT i=0; i<vAddrs.size(); i++ )
			{
				m_vThreads[i]->m_sock.Close(); 
			}
			return FALSE;
		}

		for( UINT i=0; i<vAddrs.size(); i++ )
		{
			m_vThreads[i]->Start();
		}

		for( UINT i=0; i<vAddrs.size(); i++ )
		{
			m_vThreads[i]->Wait();  
		}

		return TRUE;
	}


	BOOL ListenRun(USHORT port)
	{
		CSocket sock;
		if(!sock.Socket()) return FALSE;
		if(!sock.Bind(port)) return FALSE;
		if(!sock.Listen()) return FALSE;
		
		while(!m_bStop)
		{
			CRecvThread* th = new CRecvThread();
			if(!sock.Accept(th->m_sock)) return FALSE;
			m_vThreads.push_back(th);   
			th->m_nID = m_vThreads.size() - 1;
			
			OnInitialConnect(th->m_nID);
			th->Start();
		}

		for( UINT i=0; i<m_vThreads.size(); i++ )
		{
			m_vThreads[i]->Wait();
			delete m_vThreads[i];
		}

		return TRUE;
	}

private:
	friend class CRecvThread;
	class CRecvThread: public CThread
	{
	public:
		void ThreadMain()
		{
			CMultiSockEndpoint* pEp = CMultiSockEndpoint::GetInstance();
			while( !pEp->m_bStop )
			{
				CMsg* pMsg = pEp->RecvMsg(m_nID);
				pEp->OnReceiveMsg(m_nID, pMsg);
				pMsg->Release();
			}
			m_sock.Close();
		}
	public: 
		CSocket m_sock;
		UINT	m_nID;
		friend 	CMultiSockEndpoint;
	};
		 
protected: 
	vector<CRecvThread*> m_vThreads;
	BOOL	m_bStop;
};

#endif //__ENDPOINT_H__BY_SGCHOI