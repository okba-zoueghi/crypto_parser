#include "cp_config.h"

#define RSA_MAX_KEY_BIT_SIZE 4096
#define MODULUS_BYTE_SIZE (RSA_MAX_KEY_BIT_SIZE / 8)
#define PRIVATE_EXPONENT_BYTE_SIZE (RSA_MAX_KEY_BIT_SIZE / 8)
#define PUBLIC_EXPONENT_BYTE_SIZE 4
#define PRIME_SIZE (PRIVATE_EXPONENT_BYTE_SIZE / 2)

#define RSA_PUBLIC_KEY_OID_SIZE 9
static const CP_UINT8 RSA_PUBLIC_KEY_OID[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

typedef enum {PKCS_1, PKCS_8_UNENCRYPTED} KeyFormat;

typedef struct
{
  CP_UINT8 modulus[MODULUS_BYTE_SIZE];
  CP_UINT8 privExp[PRIVATE_EXPONENT_BYTE_SIZE];
  CP_UINT32 pubExp;
  CP_UINT8 p[PRIME_SIZE];
  CP_UINT8 q[PRIME_SIZE];
  CP_UINT8 dmp1[PRIME_SIZE];
  CP_UINT8 dmq1[PRIME_SIZE];
  CP_UINT8 iqmp[PRIME_SIZE];
  CP_UINT16 keyBitSize;
}RsaPrivateKey;

typedef struct
{
  CP_UINT8 modulus[MODULUS_BYTE_SIZE];
  CP_UINT32 pubExp;
  CP_UINT16 keyBitSize;
}RsaPublicKey;

int parseRsaPrivateKey(CP_UINT8 * keyDerInput, RsaPrivateKey * rsaKey);

int parseRsaPublicKey(CP_UINT8 * keyDerInput, RsaPublicKey * rsaKey, KeyFormat keyFormat);
