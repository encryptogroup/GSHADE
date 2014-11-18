#ifndef _HELPERS_H
#define _HELPERS_H

int HW(int a) {
	int hw = 0;
	for(int i = 0; i < sizeof(int); i++) {
		hw += (a>>i)&(1);	
	}
	return hw;
}

template <typename T>
void FreeAll( T & t ) {
    T tmp;
    t.swap( tmp );
}


#endif //HELPERS_H
