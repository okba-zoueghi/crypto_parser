#include "cp_config.h"

#define DSA_PARAM_BIT_SIZE 3072

#define DSA_PARAM_BYTE_SIZE (DSA_PARAM_BIT_SIZE / 8)

/* Digital Signature Algorithm ASN.1 structure

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

int parseDsaParam(CP_UINT8 * dsaParamDerInput, DsaParam * dsaParam);
