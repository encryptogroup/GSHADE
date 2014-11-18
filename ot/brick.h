#ifndef __brick_h__
#define __brick_h__

#include "../util/typedefs.h"

	#ifdef OTEXT_USE_GMP
#include "../util/config.h"

typedef class FixedPointExp {
public:

	FixedPointExp();
  ~FixedPointExp();

 public:
  void powerMod(mpz_t& result, mpz_t e);

  void Init(mpz_t g, mpz_t p, int fieldsize);

 private:
  mpz_t m_p;
  mpz_t m_g;
  bool m_isInitialized;
  unsigned m_numberOfElements;
  mpz_t* m_table;
} brickexp;
	#endif

#endif
