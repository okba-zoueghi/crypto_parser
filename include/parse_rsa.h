/*
  Copyright (C) 2019

  Author: okba.zoueghi@gmail.com

  This file is part of crypto_parser.

  crypto_parser is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  crypto_parser is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with crypto_parser.  If not, see <https://www.gnu.org/licenses/>.

*/

#ifndef CP_PARSE_RSA_H_
#define CP_PARSE_RSA_H_

#include "cp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RSA_MAX_KEY_BIT_SIZE 4096
#define MODULUS_BYTE_SIZE (RSA_MAX_KEY_BIT_SIZE / 8)
#define PRIVATE_EXPONENT_BYTE_SIZE (RSA_MAX_KEY_BIT_SIZE / 8)
#define PUBLIC_EXPONENT_BYTE_SIZE (RSA_MAX_KEY_BIT_SIZE / 8)
#define PRIME_SIZE (PRIVATE_EXPONENT_BYTE_SIZE / 2)

#define RSA_PUBLIC_KEY_OID_SIZE 9
extern const CP_UINT8 RSA_PUBLIC_KEY_OID[RSA_PUBLIC_KEY_OID_SIZE];

typedef enum {PKCS_1, PKCS_8_UNENCRYPTED} KeyFormat;

/* RSA private key ASN.1 structure

RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
*/

typedef struct
{
  CP_UINT8 modulus[MODULUS_BYTE_SIZE];
  CP_UINT8 privExp[PRIVATE_EXPONENT_BYTE_SIZE];
  CP_UINT8 pubExp[PUBLIC_EXPONENT_BYTE_SIZE];
  CP_UINT8 p[PRIME_SIZE];
  CP_UINT8 q[PRIME_SIZE];
  CP_UINT8 dmp1[PRIME_SIZE];
  CP_UINT8 dmq1[PRIME_SIZE];
  CP_UINT8 iqmp[PRIME_SIZE];
  CP_UINT16 keyBitSize;
}RsaPrivateKey;

/* RSA public key ASN.1

RSAPublicKey ::= SEQUENCE {
    modulus           INTEGER,  -- n
    publicExponent    INTEGER   -- e
}
*/

typedef struct
{
  CP_UINT8 modulus[MODULUS_BYTE_SIZE];
  CP_UINT8 pubExp[PUBLIC_EXPONENT_BYTE_SIZE];
  CP_UINT16 keyBitSize;
}RsaPublicKey;

/**
 * @brief Parse RSA private key
 *
 * @param[in] keyDerInput RSA private key encoded in DER format.
 * @param[in,out] rsaKey pointer to RsaPrivateKey that will hold the parsed key.
 *
 * @return CP_SUCCESS or CP_ERROR
 */
CPErrorCode parseRsaPrivateKey(CP_UINT8 * keyDerInput, RsaPrivateKey * rsaKey);

/**
 * @brief Parse RSA public key
 *
 * @param[in] keyDerInput RSA public key encoded in DER format
 * @param[in,out] rsaKey pointer to RsaPublicKey that will hold the parsed key
 * @param[in] keyFormat could be PKCS_1 or PKCS_8_UNENCRYPTED
 *
 * @return CP_SUCCESS or CP_ERROR
 */
CPErrorCode parseRsaPublicKey(CP_UINT8 * keyDerInput, RsaPublicKey * rsaKey, KeyFormat keyFormat);

#ifdef __cplusplus
}
#endif

#endif /* CP_PARSE_RSA_H_ */
