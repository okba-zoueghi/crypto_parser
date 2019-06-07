#include <stdint.h>

#define RSA_MAX_KEY_BIT_SIZE 4096
#define MODULUS_BYTE_SIZE (RSA_MAX_KEY_BIT_SIZE / 8)
#define PRIVATE_EXPONENT_BYTE_SIZE (RSA_MAX_KEY_BIT_SIZE / 8)
#define PUBLIC_EXPONENT_BYTE_SIZE 4
#define PRIME_SIZE (PRIVATE_EXPONENT_BYTE_SIZE / 2)

#define DBGMSG 1

#if DBGMSG == 1
  #define LOG_INFO(m) printf("[INFO] %s \n", m)
  #define LOG_ERROR(m) printf("[ERROR] %s \n", m)
#else
  #define LOG_INFO(m)
  #define LOG_ERROR(m)
#endif

typedef struct
{
  uint8_t modulus[MODULUS_BYTE_SIZE];
  uint8_t privExp[PRIVATE_EXPONENT_BYTE_SIZE];
  uint32_t pubExp;
  uint8_t p[PRIME_SIZE];
  uint8_t q[PRIME_SIZE];
  uint8_t dmp1[PRIME_SIZE];
  uint8_t dmq1[PRIME_SIZE];
  uint8_t iqmp[PRIME_SIZE];
  uint16_t keyBitSize;
}RsaPrivateKey;

int parseRsaPrivateKey(unsigned char * keyDerInput, RsaPrivateKey * rsaKey);
