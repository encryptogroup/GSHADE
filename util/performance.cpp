#include "performance.h"

/* 
Additional header-file that contains some variables in order to measure the performance of GMW.
Currently, the following operations are profiled: 
- number of hash invocations
- number of messages sent / received
- number of bytes sent / received
- number of asymmetric encryption / decryption operations
- number of and gates

*/

performance_statistics statistics;

