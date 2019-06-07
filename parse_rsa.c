#include "parse_der.h"
#include <string.h>
#include <stdint.h>

#include "parse_rsa.h"

int parseRsaPrivateKey(unsigned char * keyDerInput, RsaPrivateKey * rsaKey)
{
  unsigned char * sequenceOffset;
  unsigned char * versionOffset;
  unsigned char * modulusOffset;
  unsigned char * pubExpOffset;
  unsigned char * privExpOffset;
  unsigned char * pOffset;
  unsigned char * qOffset;
  unsigned char * d_mod_p1_Offset;
  unsigned char * d_mod_q1_Offset;
  unsigned char * inv_q_mod_p_Offset;

  unsigned char version;

  size_t rsaModulusByteSize;
  size_t rsaPubExpByteSize;
  size_t rsaPrivExpByteSize;
  size_t rsa_p_size;
  size_t rsa_q_size;
  size_t rsa_d_mod_p1_ByteSize;
  size_t rsa_d_mod_q1_ByteSize;
  size_t rsa_inv_q_mod_p_ByteSize;

  sequenceOffset = keyDerInput;
  if(getTag(sequenceOffset) != ASN1_SEQUENCE_TAG)
  {
    LOG_ERROR("Failed to parse the sequence");
    return -1;
  }
  LOG_INFO("Parsed the sequence");

  versionOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
  if (getTag(versionOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the sequence");
    return -1;
  }

  modulusOffset = versionOffset + getNextFieldOffset(versionOffset);
  if (getTag(modulusOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the modulus");
    return -1;
  }

  pubExpOffset = modulusOffset + getNextFieldOffset(modulusOffset);
  if (getTag(pubExpOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the public exponent");
    return -1;
  }

  privExpOffset = pubExpOffset + getNextFieldOffset(pubExpOffset);
  if (getTag(privExpOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the private exponent");
    return -1;
  }

  pOffset = privExpOffset + getNextFieldOffset(privExpOffset);
  if (getTag(pOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the the first prime p");
    return -1;
  }

  qOffset = pOffset + getNextFieldOffset(pOffset);
  if (getTag(qOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the second prime q");
    return -1;
  }

  d_mod_p1_Offset = qOffset + getNextFieldOffset(qOffset);
  if (getTag(d_mod_p1_Offset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the second prime q");
    return -1;
  }

  d_mod_q1_Offset = d_mod_p1_Offset + getNextFieldOffset(d_mod_p1_Offset);
  if (getTag(d_mod_q1_Offset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the second prime q");
    return -1;
  }

  inv_q_mod_p_Offset = d_mod_q1_Offset + getNextFieldOffset(d_mod_q1_Offset);
  if (getTag(inv_q_mod_p_Offset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the second prime q");
    return -1;
  }



  #if (DBGMSG == 1)
    int i;
  #endif

  getField( ((unsigned char *) &version) , 1, versionOffset, INCLUDE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the version :");
    printf("------- BEGIN VERSION -------\n");
    printf("%02x\n", version);
    printf("------- END VERSION -------\n");
  #endif

  rsaModulusByteSize = getField(rsaKey->modulus, MODULUS_BYTE_SIZE, modulusOffset, IGNORE_ZERO_LEADING_BYTES);
  rsaKey->keyBitSize = ((uint16_t) rsaModulusByteSize) * 8;

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the modulus :");
    printf("------- BEGIN MODULUS (n) -------\n");
    for (i = 0; i < rsaModulusByteSize; i++) {
      printf("%02x, ", rsaKey->modulus[i]);
    }
    printf("\n");
    printf("------- END MODULUS -------\n");
  #endif


  rsaPubExpByteSize = getField((unsigned char *) &(rsaKey->pubExp), PUBLIC_EXPONENT_BYTE_SIZE, pubExpOffset, IGNORE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the public exponent :");
    printf("------- BEGIN PUBLIC EXPONENT (e) -------\n");
    for (i = 0; i < rsaPubExpByteSize; i++) {
      printf("%02x, ", ((unsigned char *) &(rsaKey->pubExp))[i]);
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

  return 0;
}
