#include "parse_der.h"
#include "parse_dsa.h"

int parseDsaParam(CP_UINT8 * dsaParamDerInput, DsaParam * dsaParam)
{
	CP_UINT8 * sequenceOffset;
	CP_UINT8 * pOffset;
	CP_UINT8 * qOffset;
	CP_UINT8 * gOffset;

	sequenceOffset = dsaParamDerInput;
	if (getTag(sequenceOffset) != ASN1_SEQUENCE_TAG)
	{
		LOG_ERROR("Failed to parse the sequence");
		return -1;
	}
	LOG_INFO("Parsed the sequence");

	pOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
	if (getTag(pOffset) != ASN1_INTEGER_TAG)
	{
		LOG_ERROR("Failed to parse p");
		return -1;
	}

	qOffset = pOffset + getNextFieldOffset(pOffset);
	if (getTag(qOffset) != ASN1_INTEGER_TAG)
	{
		LOG_ERROR("Failed to parse q");
		return -1;
	}

	gOffset = qOffset + getNextFieldOffset(qOffset);
	if (getTag(gOffset) != ASN1_INTEGER_TAG)
	{
		LOG_ERROR("Failed to parse g");
		return -1;
	}

	#if (DBGMSG == 1)
    int i;
  #endif

	dsaParam->pSize = getField(dsaParam->p, DSA_PARAM_BYTE_SIZE, pOffset, IGNORE_ZERO_LEADING_BYTES);

	#if (DBGMSG == 1)
		LOG_INFO("Parsed the DSA P parameter :");
		printf("------- BEGIN DSA P -------\n");
		for (i = 0; i < dsaParam->pSize; i++) {
			printf("%02x, ", dsaParam->p[i]);
		}
		printf("\n");
		printf("------- END DSA P -------\n");
	#endif

	dsaParam->qSize = getField(dsaParam->q, DSA_PARAM_BYTE_SIZE, qOffset, IGNORE_ZERO_LEADING_BYTES);

	#if (DBGMSG == 1)
		LOG_INFO("Parsed the DSA Q parameter :");
		printf("------- BEGIN DSA Q -------\n");
		for (i = 0; i < dsaParam->qSize; i++) {
			printf("%02x, ", dsaParam->q[i]);
		}
		printf("\n");
		printf("------- END DSA Q -------\n");
	#endif

	dsaParam->gSize = getField(dsaParam->g, DSA_PARAM_BYTE_SIZE, gOffset, IGNORE_ZERO_LEADING_BYTES);

	#if (DBGMSG == 1)
		LOG_INFO("Parsed the DSA G parameter :");
		printf("------- BEGIN DSA G -------\n");
		for (i = 0; i < dsaParam->gSize; i++) {
			printf("%02x, ", dsaParam->g[i]);
		}
		printf("\n");
		printf("------- END DSA G -------\n");
	#endif

	return 0;
}
