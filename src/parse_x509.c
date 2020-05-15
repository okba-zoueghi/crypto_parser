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
#include "parse_x509.h"

const CP_UINT8 RSA_PKCS1_OID[RSA_PKCS1_OID_SIZE] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01};
const CP_UINT8 AINSI_X962_SIGNATURES_OID[AINSI_X962_OID_SIZE+1] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04};
const CP_UINT8 AINSI_X962_PUBLICKEYS_OID[AINSI_X962_OID_SIZE+1] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02};
const CP_UINT8 THAWTE_OID[THAWTE_OID_SIZE] = {0x2B, 0x65};
const CP_UINT8 ATTRIBUTE_TYPE_OID[ATTRIBUTE_TYPE_OID_SIZE] = {0x55, 0x04};
const CP_UINT8 PKCS_9_OID[PKCS_9_OID_SIZE] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09};

CPErrorCode parseX509TbsCertificate(CP_UINT8 * x509TbsCertDerOffset, TbsCertificate * tbsCertificate)
{
  CP_UINT8 * sequenceOffset = x509TbsCertDerOffset;
  CP_UINT8 * firstElementOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
  CP_UINT8 * versionOffset;
  CP_UINT8 * certificateSerialNumberOffset;
  CP_UINT8 * signatureAlgorithmOffset;
  CP_UINT8 * issuerOffset;
  CP_UINT8 * validityOffset;
  CP_UINT8 * validityNotBeforeOffset;
  CP_UINT8 * validityNotAfterOffset;
  CP_UINT8 * subjectOffset;
  CP_UINT8 * publicKeyInfoOffset;
  CP_UINT8 * publicAlgorithmIdentifierSequenceOffset;
  CP_UINT8 * publicAlgorithmIdentifierOffset;
  CP_UINT8 * publicKeyOffset;

  CP_UINT8 DerClass;
  DerClass = getClass(firstElementOffset);

  /* If the class of the first element is context specific, the the first element is the version */
  if (DerClass == CONTEXT_SPECEFIC_CLASS)
  {
    CP_UINT8 * explicitWrapper = firstElementOffset;

    if(getTag(explicitWrapper) != ASN1_CONTEXT_SPECEFIC_X509_VERSION_TAG)
    {
      LOG_ERROR("Failed to parse the version");
      return CP_ERROR;
    }

    versionOffset = explicitWrapper + getStructuredFieldDataOffset(explicitWrapper);

    if(getTag(versionOffset) != ASN1_INTEGER_TAG)
    {
      LOG_ERROR("Failed to parse the version");
      return CP_ERROR;
    }

    getField(&(tbsCertificate->version), 1, versionOffset, INCLUDE_ZERO_LEADING_BYTES);

    /*
      version 1 in encoded as 0
      version 2 is encoded as 1
      version 3 is encoded as 2
      increment to get the right version value
    */
    tbsCertificate->version += 1;

    certificateSerialNumberOffset = versionOffset + getNextFieldOffset(versionOffset);
  }
  // the class is universal, then the first element is the certificate serial number */
  else
  {
    /* The version is not specified, then use the default value */
    tbsCertificate->version = 1;

    certificateSerialNumberOffset = firstElementOffset;
  }

  #if (DBGMSG == 1)
    int i;
  #endif

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the version :");
    printf("------- BEGIN VERSION -------\n");
    printf("%02x\n", tbsCertificate->version);
    printf("------- END VERSION -------\n");
  #endif

  if(getTag(certificateSerialNumberOffset) != ASN1_INTEGER_TAG)
  {
    LOG_ERROR("Failed to parse the certificate serial number");
    return CP_ERROR;
  }

  tbsCertificate->serialNumberSize = getField(tbsCertificate->serialNumber, SERIAL_NUMBER_MAX_SIZE, certificateSerialNumberOffset, INCLUDE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
    LOG_INFO("Parsed serial number :");
    printf("------- BEGIN Serial Number -------\n");
    for (i = 0; i < tbsCertificate->serialNumberSize; i++) {
      printf("%02x, ", tbsCertificate->serialNumber[i]);
    }
    printf("\n");
    printf("------- END Serial Number -------\n");
  #endif

  signatureAlgorithmOffset = certificateSerialNumberOffset + getNextFieldOffset(certificateSerialNumberOffset);

  if (parseX509SignatureAlgorithm(signatureAlgorithmOffset, &(tbsCertificate->signatureAlgorithm)) != CP_SUCCESS)
  {
    LOG_ERROR("Failed to parse the Signature Algorithm");
    return CP_ERROR;
  }

  issuerOffset = signatureAlgorithmOffset + getNextFieldOffset(signatureAlgorithmOffset);

  if (parseX509NameAttributes(issuerOffset, &(tbsCertificate->issuer)) != CP_SUCCESS)
  {
    LOG_WARNING("Failed to parse the Name Attributes");
  }

  validityOffset = issuerOffset + getNextFieldOffset(issuerOffset);

  validityNotBeforeOffset = validityOffset + getStructuredFieldDataOffset(validityOffset);

  switch (getTag(validityNotBeforeOffset))
  {
    case ASN1_GENERALIZED_TIME_TAG:
      tbsCertificate->validity.isValidityNotBeforeInGenFormat = 1;
      break;
    case ASN1_UTC_TIME_TAG:
      tbsCertificate->validity.isValidityNotBeforeInGenFormat = 0;
      break;

    default:
      LOG_ERROR("Time format unrecognized");
      return CP_ERROR;
      break;
  }


  tbsCertificate->validity.validityNotBeforeSize = getField(tbsCertificate->validity.validityNotBefore, TIME_STRING_MAX_SIZE,
    validityNotBeforeOffset, INCLUDE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
  switch (tbsCertificate->validity.isValidityNotBeforeInGenFormat)
  {
    case 1:
      printf("Not valid before %c%c%c%c/%c%c/%c%c\n",
        tbsCertificate->validity.validityNotBefore[0],
        tbsCertificate->validity.validityNotBefore[1],
        tbsCertificate->validity.validityNotBefore[2],
        tbsCertificate->validity.validityNotBefore[3],
        tbsCertificate->validity.validityNotBefore[4],
        tbsCertificate->validity.validityNotBefore[5],
        tbsCertificate->validity.validityNotBefore[6],
        tbsCertificate->validity.validityNotBefore[7]);
      break;
    case 0:
      printf("Not valid before 20%c%c/%c%c/%c%c\n",
        tbsCertificate->validity.validityNotBefore[0],
        tbsCertificate->validity.validityNotBefore[1],
        tbsCertificate->validity.validityNotBefore[2],
        tbsCertificate->validity.validityNotBefore[3],
        tbsCertificate->validity.validityNotBefore[4],
        tbsCertificate->validity.validityNotBefore[5]);
      break;

    default:
      break;
  }
  #endif

  validityNotAfterOffset = validityNotBeforeOffset + getNextFieldOffset(validityNotBeforeOffset);

  switch (getTag(validityNotAfterOffset))
  {
    case ASN1_GENERALIZED_TIME_TAG:
      tbsCertificate->validity.isValidityNotAfterInGenFormat = 1;
      break;
    case ASN1_UTC_TIME_TAG:
      tbsCertificate->validity.isValidityNotAfterInGenFormat = 0;
      break;

    default:
      LOG_ERROR("Time format unrecognized");
      return CP_ERROR;
      break;
  }

  tbsCertificate->validity.validityNotAfterSize = getField(tbsCertificate->validity.validityNotAfter, TIME_STRING_MAX_SIZE,
    validityNotAfterOffset, INCLUDE_ZERO_LEADING_BYTES);

  #if (DBGMSG == 1)
  switch (tbsCertificate->validity.isValidityNotAfterInGenFormat)
  {
    case 1:
      printf("Not valid after %c%c%c%c/%c%c/%c%c\n",
        tbsCertificate->validity.validityNotAfter[0],
        tbsCertificate->validity.validityNotAfter[1],
        tbsCertificate->validity.validityNotAfter[2],
        tbsCertificate->validity.validityNotAfter[3],
        tbsCertificate->validity.validityNotAfter[4],
        tbsCertificate->validity.validityNotAfter[5],
        tbsCertificate->validity.validityNotAfter[6],
        tbsCertificate->validity.validityNotAfter[7]);
      break;
    case 0:
      printf("Not valid after 20%c%c/%c%c/%c%c\n",
        tbsCertificate->validity.validityNotAfter[0],
        tbsCertificate->validity.validityNotAfter[1],
        tbsCertificate->validity.validityNotAfter[2],
        tbsCertificate->validity.validityNotAfter[3],
        tbsCertificate->validity.validityNotAfter[4],
        tbsCertificate->validity.validityNotAfter[5]);
      break;

    default:
      break;
  }
  #endif

  /* TODO Parse subject */
  subjectOffset = validityOffset + getNextFieldOffset(validityOffset);
  if (parseX509NameAttributes(subjectOffset, &(tbsCertificate->subject)) != CP_SUCCESS)
  {
    LOG_WARNING("Failed to parse the Name Attributes");
  }

  publicKeyInfoOffset = subjectOffset + getNextFieldOffset(subjectOffset);

  if (getTag(publicKeyInfoOffset) != ASN1_SEQUENCE_TAG)
  {
    LOG_ERROR("Failed to parse the public key info sequence");
    return CP_ERROR;
  }

  publicAlgorithmIdentifierSequenceOffset = publicKeyInfoOffset + getStructuredFieldDataOffset(publicKeyInfoOffset);

  if (getTag(publicAlgorithmIdentifierSequenceOffset) != ASN1_SEQUENCE_TAG)
  {
    LOG_ERROR("Failed to parse the public key algorithm sequence");
    return CP_ERROR;
  }

  publicAlgorithmIdentifierOffset = publicAlgorithmIdentifierSequenceOffset + getStructuredFieldDataOffset(publicAlgorithmIdentifierSequenceOffset);

  if (getTag(publicAlgorithmIdentifierOffset) != ASN1_OID_TAG)
  {
    LOG_ERROR("Failed to parse the public key algorithm OID");
    return CP_ERROR;
  }

  tbsCertificate->publicKeyInfo.algorithmOidSize = getField(tbsCertificate->publicKeyInfo.algorithmOid, PUBLIC_KEY_OID_SIZE,
    publicAlgorithmIdentifierOffset, INCLUDE_ZERO_LEADING_BYTES);

  CP_UINT8 rsaBased = 1;
  CP_UINT8 ecdsaBased = 1;
  CP_UINT8 edDsaBased = 1;

  CP_UINT8 * oidDataOffset = publicAlgorithmIdentifierOffset + 2;

  CP_UINT8 count;

  /* look if it is RSA based algorithm */
  for (count = 0; count < RSA_PKCS1_OID_SIZE; count++)
  {
    if (oidDataOffset[count] != RSA_PKCS1_OID[count])
    {
      rsaBased = 0;
    }
  }

  /* look if it is ECDSA based algorithm */
  if (!rsaBased)
  {
    for (count = 0; count < AINSI_X962_OID_SIZE; count++)
    {
      if (oidDataOffset[count] != AINSI_X962_PUBLICKEYS_OID[count])
      {
        ecdsaBased = 0;
      }
    }
  }

  /* look if it is EdDSA based algorithm */
  if (!ecdsaBased)
  {
    for (count = 0; count < THAWTE_OID_SIZE; count++)
    {
      if (oidDataOffset[count] != THAWTE_OID[count])
      {
        edDsaBased = 0;
      }
    }
  }

  if(rsaBased)
  {
    switch (tbsCertificate->publicKeyInfo.algorithmOid[8])
    {
      case RSA_PUB_KEY_OID:
        LOG_INFO("Pulic Key Algorithm : RSA");
        tbsCertificate->publicKeyInfo.ePublicKeyInfo = PUBLIC_KEY_INFO_RSA;
        break;

      default:
        LOG_ERROR("Unrecognized Algorithm");
        tbsCertificate->publicKeyInfo.ePublicKeyInfo = PUBLIC_KEY_INFO_UNRECOGNIZED;
        return CP_ERROR;
    }
  }
  else if(ecdsaBased)
  {
    switch (tbsCertificate->publicKeyInfo.algorithmOid[6])
    {
      case ECDSA_PUB_KEY_OID:
        LOG_INFO("Pulic Key Algorithm : ECDSA");
        tbsCertificate->publicKeyInfo.ePublicKeyInfo = PUBLIC_KEY_INFO_ECDSA;
        break;

      default:
        LOG_ERROR("Unrecognized Algorithm");
        tbsCertificate->publicKeyInfo.ePublicKeyInfo = PUBLIC_KEY_INFO_UNRECOGNIZED;
        return CP_ERROR;
    }
  }
  else if(edDsaBased)
  {
    switch (tbsCertificate->publicKeyInfo.algorithmOid[2])
    {
      case ED25519_PUB_KEY_OID:
        LOG_INFO("Pulic Key Algorithm : ED25519");
        tbsCertificate->publicKeyInfo.ePublicKeyInfo = PUBLIC_KEY_INFO_ED25519;
        break;

      case ED448_PUB_KEY_OID:
        LOG_INFO("Pulic Key Algorithm : ED448");
        tbsCertificate->publicKeyInfo.ePublicKeyInfo = PUBLIC_KEY_INFO_ED448;
        break;

      default:
        LOG_ERROR("Unrecognized Algorithm");
        tbsCertificate->publicKeyInfo.ePublicKeyInfo = PUBLIC_KEY_INFO_UNRECOGNIZED;
        return CP_ERROR;
    }
  }
  else
  {
    LOG_ERROR("Unrecognized Algorithm");
    tbsCertificate->publicKeyInfo.ePublicKeyInfo = PUBLIC_KEY_INFO_UNRECOGNIZED;
    return CP_ERROR;
  }

  publicKeyOffset = publicAlgorithmIdentifierSequenceOffset + getNextFieldOffset(publicAlgorithmIdentifierSequenceOffset);

  if (getTag(publicKeyOffset) != ASN1_BIT_STRING_TAG)
  {
    LOG_ERROR("Failed to parse the public key");
    return CP_ERROR;
  }

  tbsCertificate->publicKeyInfo.publicKeySize = getField(tbsCertificate->publicKeyInfo.publicKeyBitString, PUBLIC_KEY_MAX_SIZE + 1,
    publicKeyOffset, INCLUDE_ZERO_LEADING_BYTES);

  tbsCertificate->publicKeyInfo.publicKeySize--;
  tbsCertificate->publicKeyInfo.publicKey = tbsCertificate->publicKeyInfo.publicKeyBitString + 1;

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the public key :");
    printf("------- BEGIN public key -------\n");
    for (i = 0; i < tbsCertificate->publicKeyInfo.publicKeySize; i++) {
      printf("%02x, ", tbsCertificate->publicKeyInfo.publicKey[i]);
    }
    printf("\n");
    printf("------- END public key -------\n");
  #endif

  return CP_SUCCESS;
}

CPErrorCode parseX509SignatureAlgorithm(CP_UINT8 * x509CertSigAlgDerOffset, SignatureAlgorithm * signatureAlgorithm)
{
  CP_UINT8 * sequenceOffset = x509CertSigAlgDerOffset;
  CP_UINT8 * algorithmOidOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);

  if(getTag(algorithmOidOffset) != ASN1_OID_TAG)
  {
    LOG_ERROR("Failed to parse the signature algorithm OID");
    return CP_ERROR;
  }

  signatureAlgorithm->algorithmOidSize = getField(signatureAlgorithm->algorithmOid, SIGNATURE_ALGORITHM_OID_SIZE,
    algorithmOidOffset, INCLUDE_ZERO_LEADING_BYTES);

  CP_UINT8 rsaBased = 1;
  CP_UINT8 ecdsaBased = 1;
  CP_UINT8 edDsaBased = 1;

  CP_UINT8 count;

  /* look if it is RSA based algorithm */
  for (count = 0; count < RSA_PKCS1_OID_SIZE; count++)
  {
    if (signatureAlgorithm->algorithmOid[count] != RSA_PKCS1_OID[count])
    {
      rsaBased = 0;
    }
  }

  /* look if it is ECDSA based algorithm */
  if (!rsaBased)
  {
    for (count = 0; count < AINSI_X962_OID_SIZE; count++)
    {
      if (signatureAlgorithm->algorithmOid[count] != AINSI_X962_SIGNATURES_OID[count])
      {
        ecdsaBased = 0;
      }
    }
  }

  /* look if it is EdDSA based algorithm */
  if (!ecdsaBased)
  {
    for (count = 0; count < THAWTE_OID_SIZE; count++)
    {
      if (signatureAlgorithm->algorithmOid[count] != THAWTE_OID[count])
      {
        edDsaBased = 0;
      }
    }
  }

  /* if RSA based, look which RSA algorithm is used */
  if (rsaBased)
  {
    switch (signatureAlgorithm->algorithmOid[8])
    {
      case RSA_SSA_PKCS_V_1_5_MD2_OID:
        LOG_INFO("SignatureAlgorithm :  RSA_SSA_PKCS_V_1_5_MD2");
        signatureAlgorithm->eSigAlg = RSA_SSA_PKCS_V_1_5_MD2;
        break;
      case RSA_SSA_PKCS_V_1_5_MD5_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_MD5");
        signatureAlgorithm->eSigAlg = RSA_SSA_PKCS_V_1_5_MD5;
        break;
      case RSA_SSA_PKCS_V_1_5_SHA1_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA1");
        signatureAlgorithm->eSigAlg = RSA_SSA_PKCS_V_1_5_SHA1;
        break;
      case RSA_SSA_PKCS_V_1_5_SHA224_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA224");
        signatureAlgorithm->eSigAlg = RSA_SSA_PKCS_V_1_5_SHA224;
        break;
      case RSA_SSA_PKCS_V_1_5_SHA256_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA256");
        signatureAlgorithm->eSigAlg = RSA_SSA_PKCS_V_1_5_SHA256;
        break;
      case RSA_SSA_PKCS_V_1_5_SHA384_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA384");
        signatureAlgorithm->eSigAlg = RSA_SSA_PKCS_V_1_5_SHA384;
        break;
      case RSA_SSA_PKCS_V_1_5_SHA512_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA512");
        signatureAlgorithm->eSigAlg = RSA_SSA_PKCS_V_1_5_SHA512;
        break;
      case RSA_SSA_PKCS_V_1_5_SHA_512_224_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA_512_224");
        signatureAlgorithm->eSigAlg = RSA_SSA_PKCS_V_1_5_SHA_512_224;
        break;
      case RSA_SSA_PKCS_V_1_5_SHA_512_256_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA_512_256");
        signatureAlgorithm->eSigAlg = RSA_SSA_PKCS_V_1_5_SHA_512_256;
        break;
      case RSA_SSA_PSS_OID:
        LOG_INFO("RSA_SSA_PSS");
        signatureAlgorithm->eSigAlg = RSA_SSA_PSS;
        break;

      default:
        LOG_ERROR("Unrecognized signature algorithm");
        signatureAlgorithm->eSigAlg = UNRECOGNIZED_SIGNATURE_ALGORITHM;
        return CP_ERROR;
        break;
    }
  }
  /* if ECDSA based, look which ECDSA algorithm is used */
  else if (ecdsaBased)
  {
    switch (signatureAlgorithm->algorithmOid[6])
    {
      case ECDSA_SHA1_OID:
        LOG_INFO("SignatureAlgorithm : ECDSA_SHA1");
        signatureAlgorithm->eSigAlg = ECDSA_SHA1;
        break;
      case ECDSA_SHA2_OID:
        LOG_INFO("SignatureAlgorithm : ECDSA_SHA2");
        signatureAlgorithm->eSigAlg = ECDSA_SHA2;
        break;

      default:
        LOG_ERROR("Unrecognized signature algorithm");
        signatureAlgorithm->eSigAlg = UNRECOGNIZED_SIGNATURE_ALGORITHM;
        return CP_ERROR;
        break;
    }
  }
  /* if EdDSA based, look which EdDSA algorithm is used */
  else if (edDsaBased)
  {
    switch (signatureAlgorithm->algorithmOid[2])
    {
      case ED25519_SIGNATURE_ALG_OID:
        LOG_INFO("SignatureAlgorithm : ED25519");
        signatureAlgorithm->eSigAlg = ED25519;
        break;
      case ED448_SIGNATURE_ALG_OID:
        LOG_INFO("SignatureAlgorithm : ED448");
        signatureAlgorithm->eSigAlg = ED448;
        break;

      default:
        LOG_ERROR("Unrecognized signature algorithm");
        signatureAlgorithm->eSigAlg = UNRECOGNIZED_SIGNATURE_ALGORITHM;
        return CP_ERROR;
        break;
    }
  }
  /* Algorithm Unrecognized */
  else
  {
    LOG_ERROR("Unrecognized signature algorithm");
    signatureAlgorithm->eSigAlg = UNRECOGNIZED_SIGNATURE_ALGORITHM;
    return CP_ERROR;
  }

  return CP_SUCCESS;
}

CPErrorCode parseX509SignatureValue(CP_UINT8 * x509CertSigValDerOffset, SignatureValue * signatureValue)
{
  if(getTag(x509CertSigValDerOffset) != ASN1_BIT_STRING_TAG)
  {
    LOG_ERROR("Failed to parse the signature value");
    return CP_ERROR;
  }

  signatureValue->signatureValueSize = getField(signatureValue->signatureValueBitString, SIGNATURE_SIZE, x509CertSigValDerOffset,
    INCLUDE_ZERO_LEADING_BYTES);

  /* Ignore the first byte as it belongs to header of the bit string */
  signatureValue->signatureValue = signatureValue->signatureValueBitString + 1;
  signatureValue->signatureValueSize -= 1;

  #if (DBGMSG == 1)
    int i;
  #endif

  #if (DBGMSG == 1)
    LOG_INFO("Parsed the signature value :");
    printf("------- BEGIN signature value -------\n");
    for (i = 0; i < signatureValue->signatureValueSize; i++) {
      printf("%02x, ", signatureValue->signatureValue[i]);
    }
    printf("\n");
    printf("------- END signature value -------\n");
  #endif

  return CP_SUCCESS;
}

CPErrorCode parseX509NameAttributes(CP_UINT8 * x509NameAttributesOffset, NameAttributes * nameAttributes)
{
  CP_UINT8 * endOfNameAttributesOffset = x509NameAttributesOffset + getNextFieldOffset(x509NameAttributesOffset);
  CP_UINT8 * attributeSetOffset = x509NameAttributesOffset + getStructuredFieldDataOffset(x509NameAttributesOffset);

  nameAttributes->stateSize = 0;
  nameAttributes->organizationSize = 0;
  nameAttributes->commonNameSize = 0;
  nameAttributes->emailAddressSize = 0;

  do
  {
    if (getTag(attributeSetOffset) != ASN1_SET_TAG)
    {
      LOG_ERROR("Failed to parse the attribute set");
      return CP_ERROR;
    }

    CP_UINT8 * attributeSequenceOffset = attributeSetOffset + getStructuredFieldDataOffset(attributeSetOffset);

    if (getTag(attributeSequenceOffset) != ASN1_SEQUENCE_TAG)
    {
      LOG_ERROR("Failed to parse the attribute sequence");
      return CP_ERROR;
    }

    CP_UINT8 * attributeOidOffset = attributeSequenceOffset + getStructuredFieldDataOffset(attributeSequenceOffset);

    if (getTag(attributeOidOffset) != ASN1_OID_TAG)
    {
      LOG_ERROR("Failed to parse the attribute OID");
      return CP_ERROR;
    }

    CP_UINT8 * oidDataOffset = attributeOidOffset + 2;

    CP_UINT8 count;
    CP_UINT8 x520NameAttribute = 1;
    CP_UINT8 pkcs9Attribute = 1;

    for (count = 0; count < ATTRIBUTE_TYPE_OID_SIZE; count++)
    {
      if (oidDataOffset[count] != ATTRIBUTE_TYPE_OID[count])
      {
        x520NameAttribute = 0;
      }
    }

    if (!x520NameAttribute)
    {
      for (count = 0; count < PKCS_9_OID_SIZE; count++)
      {
        if (oidDataOffset[count] != PKCS_9_OID[count])
        {
          pkcs9Attribute = 0;
        }
      }
    }

    #if (DBGMSG == 1)
      int i;
    #endif

    CP_UINT8 * attributeDataOffset = attributeOidOffset + getNextFieldOffset(attributeOidOffset);

    if (x520NameAttribute)
    {
      switch (oidDataOffset[2])
      {
        case ATTRIBUTE_TYPE_COUNTRY_NAME_OID:

          if (getTag(attributeDataOffset) != ASN1_PRINTABLE_STRING_TAG)
          {
            LOG_ERROR("Failed to parse the country name");
            return CP_ERROR;
          }

          getField(nameAttributes->country, COUNTRY_NAME_SIZE, attributeDataOffset, INCLUDE_ZERO_LEADING_BYTES);

          #if (DBGMSG == 1)
            LOG_INFO("Parsed country name:");
            printf("------- BEGIN country name -------\n");
            for (i = 0; i < COUNTRY_NAME_SIZE; i++) {
              printf("%C", nameAttributes->country[i]);
            }
            printf("\n");
            printf("------- END country name -------\n");
          #endif

          break;

        case ATTRIBUTE_TYPE_STATE_OR_PROVINCE_NAME_OID:

          nameAttributes->stateSize = getField(nameAttributes->state, STATE_OR_PROVINCE_NAME_MAX_SIZE,
            attributeDataOffset, INCLUDE_ZERO_LEADING_BYTES);

          #if (DBGMSG == 1)
            LOG_INFO("Parsed state:");
            printf("------- BEGIN state -------\n");
            for (i = 0; i < nameAttributes->stateSize; i++) {
              printf("%c", nameAttributes->state[i]);
            }
            printf("\n");
            printf("------- END state -------\n");
          #endif

          break;

        case ATTRIBUTE_TYPE_ORGANIZATION_NAME_OID:

          nameAttributes->organizationSize = getField(nameAttributes->organization, ORGANIZATION_NAME_MAX_SIZE,
            attributeDataOffset, INCLUDE_ZERO_LEADING_BYTES);

          #if (DBGMSG == 1)
            LOG_INFO("Parsed organization:");
            printf("------- BEGIN organization -------\n");
            for (i = 0; i < nameAttributes->organizationSize; i++) {
              printf("%c", nameAttributes->organization[i]);
            }
            printf("\n");
            printf("------- END organization -------\n");
          #endif

          break;

        case ATTRIBUTE_TYPE_COMMON_NAME_OID:

          nameAttributes->commonNameSize = getField(nameAttributes->commonName, COMMON_NAME_MAX_SIZE,
            attributeDataOffset, INCLUDE_ZERO_LEADING_BYTES);

          #if (DBGMSG == 1)
            LOG_INFO("Parsed common name:");
            printf("------- BEGIN common name -------\n");
            for (i = 0; i < nameAttributes->commonNameSize; i++) {
              printf("%c", nameAttributes->commonName[i]);
            }
            printf("\n");
            printf("------- END common name -------\n");
          #endif

          break;

        default:
          break;
      }
    }
    else if (pkcs9Attribute)
    {
      switch (oidDataOffset[8])
      {
        case ATTRIBUTE_TYPE_EMAIL_ADDRESS_OID:

          if (getTag(attributeDataOffset) != ASN1_IA5_STRING_TAG)
          {
            LOG_ERROR("Failed to parse the email address");
            return CP_ERROR;
          }

          nameAttributes->emailAddressSize = getField(nameAttributes->emailAddress, EMAIL_ADDRESS_MAX_SIZE,
            attributeDataOffset, INCLUDE_ZERO_LEADING_BYTES);

          break;

        default:
          break;
      }
    }
    else
    {
      LOG_WARNING("Attribute OID Unknown");
    }

  } while((attributeSetOffset += getNextFieldOffset(attributeSetOffset)) != endOfNameAttributesOffset);

  return CP_SUCCESS;
}

CPErrorCode parseX509Cert(CP_UINT8 * x509CertDerInput, X509Cert * x509Cert)
{
  CPErrorCode ret = CP_SUCCESS;

  CP_UINT8 * sequenceOffset;

  /* tbsCertificate offsets*/
  CP_UINT8 * tbsCertificateOffset;

  /* signatureAlgorithm offsets*/
  CP_UINT8 * signatureAlgorithmOffset;

  /* signatureValue offsets */
  CP_UINT8 * signatureValueOffset;

  sequenceOffset = x509CertDerInput;

  if(getTag(sequenceOffset) != ASN1_SEQUENCE_TAG)
  {
    LOG_ERROR("Failed to parse the sequence");
    return CP_ERROR;
  }
  LOG_INFO("Parsed the sequence");

  /* Parse tbsCertificate */
  tbsCertificateOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
  ret = parseX509TbsCertificate(tbsCertificateOffset, &(x509Cert->tbsCertificate));

  if (ret != CP_SUCCESS)
  {
    LOG_ERROR("Failed to parse the TbsCertificate");
    return ret;
  }

  LOG_INFO("Parsed the TbsCertificate");

  /* Parse the signature algorithm */
  signatureAlgorithmOffset = tbsCertificateOffset + getNextFieldOffset(tbsCertificateOffset);
  ret = parseX509SignatureAlgorithm(signatureAlgorithmOffset, &(x509Cert->signatureAlgorithm));

  if (ret != CP_SUCCESS)
  {
    LOG_ERROR("Failed to parse the Signature Algorithm");
    return ret;
  }

  LOG_INFO("Parsed the the Signature Algorithm");

  /* Parse the signature value */
  signatureValueOffset = signatureAlgorithmOffset + getNextFieldOffset(signatureAlgorithmOffset);
  ret = parseX509SignatureValue(signatureValueOffset, &(x509Cert->signatureValue));

  if (ret != CP_SUCCESS)
  {
    LOG_ERROR("Failed to parse the Signature Value");
    return ret;
  }

  LOG_INFO("Parsed the the Signature Value");

  return ret;
}
