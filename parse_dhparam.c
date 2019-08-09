#include "parse_der.h"
#include "parse_dhparam.h"

int parseDhParam(CP_UINT8 * dhParamDerInput, DhParam * dhParam)
{
	CP_UINT8 * sequenceOffset;
	CP_UINT8 * dhPrimeOffset;
	CP_UINT8 * dhGeneratorOffset;

	sequenceOffset = dhParamDerInput;
	if(getTag(sequenceOffset) != ASN1_SEQUENCE_TAG)
	{
		LOG_ERROR("Failed to parse the sequence");
		return -1;
	}
	LOG_INFO("Parsed the sequence");

	dhPrimeOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
  if (getTag(dhPrimeOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the dhPrime");
    return -1;
  }

	dhGeneratorOffset = dhPrimeOffset + getNextFieldOffset(dhPrimeOffset);
  if (getTag(dhGeneratorOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the dhGenerator");
    return -1;
  }

	#if (DBGMSG == 1)
		int i;
	#endif

	dhParam->dhPrimeSize = getField(dhParam->dhPrime, DH_PARAM_BYTE_SIZE, dhPrimeOffset, IGNORE_ZERO_LEADING_BYTES);

	#if (DBGMSG == 1)
		LOG_INFO("Parsed the DH Prime :");
		printf("------- BEGIN DH Prime (p) -------\n");
		for (i = 0; i < dhParam->dhPrimeSize; i++) {
			printf("%02x, ", dhParam->dhPrime[i]);
		}
		printf("\n");
		printf("------- END DH Prime -------\n");
	#endif

	dhParam->dhGeneratorSize = getField(dhParam->dhGenerator, DH_PARAM_BYTE_SIZE, dhGeneratorOffset, IGNORE_ZERO_LEADING_BYTES);

	#if (DBGMSG == 1)
		LOG_INFO("Parsed the DH Generator :");
		printf("------- BEGIN DH Generator (g) -------\n");
		for (i = 0; i < dhParam->dhGeneratorSize; i++) {
			printf("%02x, ", dhParam->dhGenerator[i]);
		}
		printf("\n");
		printf("------- END DH Generator -------\n");
	#endif

	return 0;
}
