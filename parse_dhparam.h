#include "cp_config.h"

#define DH_PARAM_BIT_SIZE 1024

#define DH_PARAM_BYTE_SIZE (DH_PARAM_BIT_SIZE / 8)

/* Diffie Hellman parameters ASN.1 structure

DHParameter ::= SEQUENCE {
 prime INTEGER, -- p
 base INTEGER, -- g
 privateValueLength INTEGER OPTIONAL }
*/

typedef struct
{
	CP_UINT8 dhPrime[DH_PARAM_BYTE_SIZE];
	CP_UINT16 dhPrimeSize;
	CP_UINT8 dhGenerator[DH_PARAM_BYTE_SIZE];
	CP_UINT16 dhGeneratorSize;
}DhParam;

int parseDhParam(CP_UINT8 * dhParamDerInput, DhParam * dhParam);
