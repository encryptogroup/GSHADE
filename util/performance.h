/* 
TODO: implement performance measurement a class-structure and add semaphores to make it multi-threading safe!

Additional header-file that contains some variables in order to measure the performance of GMW.
Currently, the following operations are profiled: 
- number of hash invocations
- number of messages sent / received
- number of bytes sent / received
- number of asymmetric encryption / decryption operations

*/
#ifndef PERFORMANCE_H
#define PERFORMANCE_H
#include <sys/time.h>
#include "thread.h"
#include <ctime>

struct performance_statistics {
	unsigned int hash_invocations, hi_IKNP_snd_first, hi_IKNP_snd_second, hi_IKNP_rcv_first, hi_IKNP_rcv_second, hi_bitvector, messages_sent, messages_received, bytes_sent, bytes_received, encryptions, decryptions, andgates, gates, depth;
	timeval pbegin, pend, conbegin, conend, otbegin, otend, opbegin, opend, npbegin, npend, tempbegin, tempend, temp2begin, temp2end, temp3begin, temp3end, tempbegin_snd, tempend_snd, tempbegin2_snd, tempend2_snd, tempbegin3_snd, tempend3_snd, tempbegin4_snd, tempend4_snd, acc_time_sender_aes_begin, acc_time_sender_aes_end, acc_time_receiver_aes_begin, acc_time_receiver_aes_end, acc_time_sender_sha_begin, acc_time_sender_sha_end, acc_time_receiver_sha_begin, acc_time_receiver_sha_end, acc_time_sender_matrix_transposion_begin, acc_time_sender_matrix_transposion_end, acc_time_receiver_matrix_transposion_begin, acc_time_receiver_matrix_transposion_end, acc_time_rnd_generation_begin, acc_time_rnd_generation_end, acc_time_sender_mt_begin, acc_time_sender_mt_end, acc_time_receiver_mt_begin, acc_time_receiver_mt_end, time_circuit_generation_begin, time_circuit_generation_end, acc_time_transmission_sender_begin, acc_time_transmission_sender_end, acc_time_transmission_receiver_begin, acc_time_transmission_receiver_end; //time of protocol begin, protocol end, ot begin, ot end, online-phase begin, online phase end
	double time_rnd_generation;
	CLock *mutex;
};

#endif //PERFORMANCE_H
