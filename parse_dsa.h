#include "cp_config.h"

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

int parseDsaParam(CP_UINT8 * dsaParamDerInput, DsaParam * dsaParam);

/* TO DO
int parseDsaPrivateKey(CP_UINT8 * dsaPrivateKeyDerInput, DsaPrivateKey * dsaPrivateKey);
int parseDsaPublicKey(CP_UINT8 * dsaPublicKeyDerInput, DsaPublicKey * dsaPublicKey);
*/
