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

#ifndef CP_PARSE_DHPARAM_H_
#define CP_PARSE_DHPARAM_H_

#include "cp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/**
 * @brief Parse Diffie Hellman parameters
 *
 * @param[in] dhParamDerInput Diffie Hellman parameters encoded in DER format
 * @param[in,out] dhParam pointer to DhParam that will hold the parsed parameters
 *
 * @return CP_SUCCESS or CP_ERROR
 */
CPErrorCode parseDhParam(CP_UINT8 * dhParamDerInput, DhParam * dhParam);

#ifdef __cplusplus
}
#endif

#endif /* CP_PARSE_DHPARAM_H_ */
