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

#include "parse_der.h"
#include "parse_dhparam.h"

CPErrorCode parseDhParam(CP_UINT8 * dhParamDerInput, DhParam * dhParam)
{
	CP_UINT8 * sequenceOffset;
	CP_UINT8 * dhPrimeOffset;
	CP_UINT8 * dhGeneratorOffset;

	sequenceOffset = dhParamDerInput;
	if(getTag(sequenceOffset) != ASN1_SEQUENCE_TAG)
	{
	  LOG_ERROR("Failed to parse the sequence");
	  return CP_ERROR;
	}
	LOG_INFO("Parsed the sequence");

	dhPrimeOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
  	if (getTag(dhPrimeOffset) != ASN1_INTEGER_TAG)
  	{
    	  LOG_ERROR("Failed to parse the dhPrime");
    	  return CP_ERROR;
  	}

	dhGeneratorOffset = dhPrimeOffset + getNextFieldOffset(dhPrimeOffset);
  	if (getTag(dhGeneratorOffset) != ASN1_INTEGER_TAG)
  	{
    	  LOG_ERROR("Failed to parse the dhGenerator");
    	  return CP_ERROR;
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

	return CP_SUCCESS;
}
