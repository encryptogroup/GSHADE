#ifndef __CQUEUE__
#define __CQUEUE__

#include "typedefs.h"
class CQueue
{
	private:
		int queuesize;
		int head;
		int tail;
		int* queue;
	public: 
		CQueue(int maxsize);
		~CQueue(){if(queue) free(queue); };
		void enq(int ele);
		int deq();
		int size();

};

#endif
