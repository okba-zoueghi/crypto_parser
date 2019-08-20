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

#include "cp_config.h"

/* Masks */
#define CLASS_MASK 0xC0
#define STRUCTURED_FIELD_MASK 0x20
#define TAG_MASK 0x1F

/* Classes */
#define UNIVERSAL_CLASS 0x00
#define APPLCATION_CLASS 0x40
#define CONTEXT_SPECEFIC_CLASS 0x80
#define PRIVATE_CLASS 0xC0

/* Universal Tags */
#define ASN1_SEQUENCE_TAG 0x10
#define ASN1_BOOLEAN_TAG 0x01
#define ASN1_INTEGER_TAG 0x02
#define ASN1_BIT_STRING_TAG 0x03
#define AS1_OCTET_STRING_TAG 0x04
#define ASN1_NULL_TAG 0x05
#define ASN1_OID_TAG 0x06
#define ASN1_TIME_TAG 0x0A
#define ASN1_UTC_TIME_TAG 0x17
#define ASN1_GENERALIZED_TIME_TAG 0x18
#define ASN1_PRINTABLE_STRING_TAG 0x13
#define ASN1_UNIVERSAL_STRING_TAG 0x1C
#define ASN1_UTF8_STRING_TAG 0x0C
#define ASN1_BMP_STRING_TAG 0x1E

/* Context Specefic Tags */
#define ASN1_CONTEXT_SPECEFIC_X509_VERSION_TAG 0

/* Others */
#define MAX_ONE_BYTE_LENGTH 0x80
#define MIN_ONE_BYTE_LENGTH 0x00
#define IGNORE_ZERO_LEADING_BYTES 1
#define INCLUDE_ZERO_LEADING_BYTES 0

//Same as memcpy provided by the C standard library
void CP_memcpy(CP_UINT8 * dest, const CP_UINT8 * src, CP_UINT32 len);

// this function is only for internal usage
static CP_UINT32 getFirstNonZeroByteOffset(CP_UINT8 * input, CP_UINT32 bufferSize);

CP_UINT32 isFieldStructured(CP_UINT8 * input);

CP_UINT32 getStructuredFieldDataOffset(CP_UINT8 * input);

CP_UINT32 getTag(CP_UINT8 * input);

CP_UINT8 getClass(CP_UINT8 * input);

//this function is only for internal usage
static CP_UINT32 getExtendedSizeField(CP_UINT8 * input, CP_UINT32 sizeFieldLength);

CP_UINT32 getNextFieldOffset(CP_UINT8 * input);

CP_UINT32 getField(CP_UINT8 * buffer, CP_UINT32 bufferSize, CP_UINT8 * input, CP_UINT8 ignoreZeroLeadingBytes);
