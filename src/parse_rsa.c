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
#include "parse_rsa.h"

const CP_UINT8 RSA_PUBLIC_KEY_OID[RSA_PUBLIC_KEY_OID_SIZE] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

CPErrorCode parseRsaPrivateKey(CP_UINT8 * keyDerInput, RsaPrivateKey * rsaKey)
{
  CP_UINT8 * sequenceOffset;
  CP_UINT8 * versionOffset;
  CP_UINT8 * modulusOffset;
  CP_UINT8 * pubExpOffset;
  CP_UINT8 * privExpOffset;
  CP_UINT8 * pOffset;
  CP_UINT8 * qOffset;
  CP_UINT8 * d_mod_p1_Offset;
  CP_UINT8 * d_mod_q1_Offset;
  CP_UINT8 * inv_q_mod_p_Offset;

  CP_UINT8 version;

  CP_UINT32 rsaModulusByteSize;
  CP_UINT32 rsaPubExpByteSize;
  CP_UINT32 rsaPrivExpByteSize;
  CP_UINT32 rsa_p_size;
  CP_UINT32 rsa_q_size;
  CP_UINT32 rsa_d_mod_p1_ByteSize;
  CP_UINT32 rsa_d_mod_q1_ByteSize;
  CP_UINT32 rsa_inv_q_mod_p_ByteSize;

  sequenceOffset = keyDerInput;
  if(getTag(sequenceOffset) != ASN1_SEQUENCE_TAG)
  {
    LOG_ERROR("Failed to parse the sequence");
    return CP_ERROR;
  }
  LOG_INFO("Parsed the sequence");

  versionOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
  if (getTag(versionOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the sequence");
    return CP_ERROR;
  }

  modulusOffset = versionOffset + getNextFieldOffset(versionOffset);
  if (getTag(modulusOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the modulus");
    return CP_ERROR;
  }

  pubExpOffset = modulusOffset + getNextFieldOffset(modulusOffset);
  if (getTag(pubExpOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the public exponent");
    return CP_ERROR;
  }

  privExpOffset = pubExpOffset + getNextFieldOffset(pubExpOffset);
  if (getTag(privExpOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the private exponent");
    return CP_ERROR;
  }

  pOffset = privExpOffset + getNextFieldOffset(privExpOffset);
  if (getTag(pOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the the first prime p");
    return CP_ERROR;
  }

  qOffset = pOffset + getNextFieldOffset(pOffset);
  if (getTag(qOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the second prime q");
    return CP_ERROR;
  }

  d_mod_p1_Offset = qOffset + getNextFieldOffset(qOffset);
  if (getTag(d_mod_p1_Offset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the second prime q");
    return CP_ERROR;
  }

  d_mod_q1_Offset = d_mod_p1_Offset + getNextFieldOffset(d_mod_p1_Offset);
  if (getTag(d_mod_q1_Offset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the second prime q");
    return CP_ERROR;
  }

  inv_q_mod_p_Offset = d_mod_q1_Offset + getNextFieldOffset(d_mod_q1_Offset);
  if (getTag(inv_q_mod_p_Offset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the second prime q");
    return CP_ERROR;
  }



  #if (DBGMSG == 1)
    int i;
  #endif

  getField( ((CP_UINT8 *) &version) , 1, versionOffset, INCLUDE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the version :");
    printf("------- BEGIN VERSION -------\n");
    printf("%02x\n", version);
    printf("------- END VERSION -------\n");
  #endif

  rsaModulusByteSize = getField(rsaKey->modulus, MODULUS_BYTE_SIZE, modulusOffset, IGNORE_ZERO_LEADING_BYTES);
  rsaKey->keyBitSize = ((CP_UINT16) rsaModulusByteSize) * 8;

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the modulus :");
    printf("------- BEGIN MODULUS (n) -------\n");
    for (i = 0; i < rsaModulusByteSize; i++) {
      printf("%02x, ", rsaKey->modulus[i]);
    }
    printf("\n");
    printf("------- END MODULUS -------\n");
  #endif


  rsaPubExpByteSize = getField(rsaKey->pubExp, PUBLIC_EXPONENT_BYTE_SIZE, pubExpOffset, IGNORE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the public exponent hhhh :");
    printf("------- BEGIN PUBLIC EXPONENT (e) -------\n");
    for (i = 0; i < rsaPubExpByteSize; i++) {
      printf("%02x, ", rsaKey->pubExp[i]);
    }
    printf("\n");
    printf("------- END PUBLIC EXPONENT -------\n");
  #endif


  rsaPrivExpByteSize = getField(rsaKey->privExp, PRIVATE_EXPONENT_BYTE_SIZE, privExpOffset, IGNORE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the private exponent :");
    printf("------- BEGIN PRIVATE EXPONENT (d) -------\n");
    for (i = 0; i < rsaPrivExpByteSize; i++) {
      printf("%02x, ", rsaKey->privExp[i]);
    }
    printf("\n");
    printf("------- END PRIVATE EXPONENT -------\n");
  #endif

  rsa_p_size = getField(rsaKey->p, PRIME_SIZE, pOffset, IGNORE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the first prime :");
    printf("------- BEGIN FIRST PRIME (p) -------\n");
    for (i = 0; i < rsa_p_size; i++) {
      printf("%02x, ", rsaKey->p[i]);
    }
    printf("\n");
    printf("------- END FIRST PRIME -------\n");
  #endif

  rsa_q_size = getField(rsaKey->q, PRIME_SIZE, qOffset, IGNORE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the first prime :");
    printf("------- BEGIN SECOND PRIME (q) -------\n");
    for (i = 0; i < rsa_q_size; i++) {
      printf("%02x, ", rsaKey->q[i]);
    }
    printf("\n");
    printf("------- END SECOND PRIME -------\n");
  #endif

  rsa_d_mod_p1_ByteSize = getField(rsaKey->dmp1, PRIME_SIZE, d_mod_p1_Offset, IGNORE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed (d mod p-1) :");
    printf("------- BEGIN (d mod p-1) -------\n");
    for (i = 0; i < rsa_d_mod_p1_ByteSize; i++) {
      printf("%02x, ", rsaKey->dmp1[i]);
    }
    printf("\n");
    printf("------- END -------\n");
  #endif

  rsa_d_mod_q1_ByteSize = getField(rsaKey->dmq1, PRIME_SIZE, d_mod_q1_Offset, IGNORE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed (d mod q-1) :");
    printf("------- BEGIN (d mod q-1) -------\n");
    for (i = 0; i < rsa_d_mod_q1_ByteSize; i++) {
      printf("%02x, ", rsaKey->dmq1[i]);
    }
    printf("\n");
    printf("------- END -------\n");
  #endif

  rsa_inv_q_mod_p_ByteSize = getField(rsaKey->iqmp, PRIME_SIZE, inv_q_mod_p_Offset, IGNORE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed (inverse of q) mod p :");
    printf("------- BEGIN (inverse of q) mod p -------\n");
    for (i = 0; i < rsa_inv_q_mod_p_ByteSize; i++) {
      printf("%02x, ", rsaKey->iqmp[i]);
    }
    printf("\n");
    printf("------- END -------\n");
  #endif

  return CP_SUCCESS;
}

CPErrorCode parseRsaPublicKey(CP_UINT8 * keyDerInput, RsaPublicKey * rsaKey, KeyFormat keyFormat)
{
  CP_UINT8 * modulusOffset;
  CP_UINT8 * pubExpOffset;
  CP_UINT32 rsaModulusByteSize;
  CP_UINT32 rsaPubExpByteSize;

  if (keyFormat == PKCS_8_UNENCRYPTED)
  {
    CP_UINT8 * outerSequenceOffset;
    CP_UINT8 * innerSequenceOffset;
    CP_UINT8 * oidOffset;
    CP_UINT8 * nullOffset;
    CP_UINT8 * bitStringOffset;
    CP_UINT8 * bitStringSequenceOffset;

    outerSequenceOffset = keyDerInput;

    if(getTag(outerSequenceOffset) != ASN1_SEQUENCE_TAG)
    {
      LOG_ERROR("Failed to parse the sequence");
      return CP_ERROR;
    }

    innerSequenceOffset = outerSequenceOffset + getStructuredFieldDataOffset(outerSequenceOffset);

    if(getTag(innerSequenceOffset) != ASN1_SEQUENCE_TAG)
    {
      LOG_ERROR("Failed to parse the sequence");
      return CP_ERROR;
    }

    oidOffset = innerSequenceOffset + getStructuredFieldDataOffset(innerSequenceOffset);

    if(getTag(oidOffset) != ASN1_OID_TAG)
    {
      LOG_ERROR("Failed to parse the oid");
      return CP_ERROR;
    }

    CP_UINT8 * oidDataOffset = oidOffset + 2;

    CP_UINT8 count;
    for (count = 0; count < RSA_PUBLIC_KEY_OID_SIZE; count++)
    {
      if (oidDataOffset[count] != RSA_PUBLIC_KEY_OID[count])
      {
        LOG_ERROR("The Object Identifier doesn't correspond to public key");
        return CP_ERROR;
      }
    }

    nullOffset = oidOffset + getNextFieldOffset(oidOffset);

    if(getTag(nullOffset) != ASN1_NULL_TAG)
    {
      LOG_ERROR("Failed to parse the null field");
      return CP_ERROR;
    }

    bitStringOffset = innerSequenceOffset + getNextFieldOffset(innerSequenceOffset);

    if(getTag(bitStringOffset) != ASN1_BIT_STRING_TAG)
    {
      LOG_ERROR("Failed to parse the bit string");
      return CP_ERROR;
    }

    bitStringSequenceOffset = bitStringOffset + getStructuredFieldDataOffset(bitStringOffset) + 1;// +1 -> ignore the first byte of the data

    if(getTag(bitStringSequenceOffset) != ASN1_SEQUENCE_TAG)
    {
      LOG_ERROR("Failed to parse the sequence");
      return CP_ERROR;
    }

    modulusOffset = bitStringSequenceOffset + getStructuredFieldDataOffset(bitStringSequenceOffset);
  }
  else if (keyFormat == PKCS_1)
  {
    CP_UINT8 * sequenceOffset;

    sequenceOffset = keyDerInput;
    if(getTag(sequenceOffset) != ASN1_SEQUENCE_TAG)
    {
      LOG_ERROR("Failed to parse the sequence");
      return CP_ERROR;
    }
    LOG_INFO("Parsed the sequence");

    modulusOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
  }
  else
  {
    LOG_ERROR("Key format unkown");
    return CP_ERROR;
  }


  if (getTag(modulusOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the modulus");
    return CP_ERROR;
  }

  pubExpOffset = modulusOffset + getNextFieldOffset(modulusOffset);
  if (getTag(pubExpOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the public exponent");
    return CP_ERROR;
  }

  #if (DBGMSG == 1)
    int i;
  #endif

  rsaModulusByteSize = getField(rsaKey->modulus, MODULUS_BYTE_SIZE, modulusOffset, IGNORE_ZERO_LEADING_BYTES);
  rsaKey->keyBitSize = ((CP_UINT16) rsaModulusByteSize) * 8;

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the modulus :");
    printf("------- BEGIN MODULUS (n) -------\n");
    for (i = 0; i < rsaModulusByteSize; i++) {
      printf("%02x, ", rsaKey->modulus[i]);
    }
    printf("\n");
    printf("------- END MODULUS -------\n");
  #endif


  rsaPubExpByteSize = getField(rsaKey->pubExp, PUBLIC_EXPONENT_BYTE_SIZE, pubExpOffset, IGNORE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the public exponent :");
    printf("------- BEGIN PUBLIC EXPONENT (e) -------\n");
    for (i = 0; i < rsaPubExpByteSize; i++) {
      printf("%02x, ", rsaKey->pubExp[i]);
    }
    printf("\n");
    printf("------- END PUBLIC EXPONENT -------\n");
  #endif


}
