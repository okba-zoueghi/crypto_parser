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

#ifndef CP_PARSE_DSA_H_
#define CP_PARSE_DSA_H_

#include "cp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DSA_PARAM_BIT_SIZE 3072

#define DSA_PARAM_BYTE_SIZE (DSA_PARAM_BIT_SIZE / 8)

/* Digital Signature Algorithm Parameters ASN.1 structure

DSA-Parms  ::=  SEQUENCE  {
    p INTEGER,
    q INTEGER,
    g INTEGER
}
*/

typedef struct
{
	CP_UINT8 p[DSA_PARAM_BYTE_SIZE];
	CP_UINT16 pSize;
	CP_UINT8 q[DSA_PARAM_BYTE_SIZE];
	CP_UINT16 qSize;
	CP_UINT8 g[DSA_PARAM_BYTE_SIZE];
	CP_UINT16 gSize;
}DsaParam;

/* Digital Signature Algorithm Private Key structure
Not standardized, the ASN.1 structure below is used by OpenSSL

DSAPrivatKey_OpenSSL ::= SEQUENCE
   version INTEGER,
   p INTEGER,
   q INTEGER,
   g INTEGER,
   y INTEGER,
   x INTEGER
}
*/

/* TO DO
typedef struct
{

}DsaPrivateKey;
*/

/* Digital Signature Algorithm Public Key ASN.1 structure
DSAPublicKey ::= INTEGER
*/

/* TO DO
typedef struct
{

}DsaPublicKey;
*/

CPErrorCode parseDsaParam(CP_UINT8 * dsaParamDerInput, DsaParam * dsaParam);

/* TO DO
CPErrorCode parseDsaPrivateKey(CP_UINT8 * dsaPrivateKeyDerInput, DsaPrivateKey * dsaPrivateKey);
CPErrorCode parseDsaPublicKey(CP_UINT8 * dsaPublicKeyDerInput, DsaPublicKey * dsaPublicKey);
*/

#ifdef __cplusplus
}
#endif

#endif /* CP_PARSE_DSA_H_ */
