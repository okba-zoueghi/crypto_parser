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

int parseX509TbsCertificate(CP_UINT8 * x509TbsCertDerOffset, TbsCertificate * tbsCertificate)
{
  CP_UINT8 * sequenceOffset = x509TbsCertDerOffset;
  CP_SINT8 * firstElementOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
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

  CP_UINT8 class;
  class = getClass(firstElementOffset);

  CP_UINT8 isFirstElementVersion;

  /* If the class of the first element is context specific, the the first element is the version */
  if (class == CONTEXT_SPECEFIC_CLASS)
  {
    CP_UINT8 * explicitWrapper = firstElementOffset;

    if(getTag(explicitWrapper) != ASN1_CONTEXT_SPECEFIC_X509_VERSION_TAG)
    {
      LOG_ERROR("Failed to parse the version");
      return -1;
    }

    versionOffset = explicitWrapper + getStructuredFieldDataOffset(explicitWrapper);

    if(getTag(versionOffset) != ASN1_INTEGER_TAG)
    {
      LOG_ERROR("Failed to parse the version");
      return -1;
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
    return -1;
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
  parseX509SignatureAlgorithm(signatureAlgorithmOffset, &(tbsCertificate->signatureAlgorithm));

  issuerOffset = signatureAlgorithmOffset + getNextFieldOffset(signatureAlgorithmOffset);
  parseX509NameAttributes(issuerOffset, &(tbsCertificate->issuer));

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
      return -1;
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
      return -1;
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
  parseX509NameAttributes(subjectOffset, &(tbsCertificate->subject));

  publicKeyInfoOffset = subjectOffset + getNextFieldOffset(subjectOffset);

  if (getTag(publicKeyInfoOffset) != ASN1_SEQUENCE_TAG)
  {
    LOG_ERROR("Failed to parse the public key info sequence");
    return -1;
  }

  publicAlgorithmIdentifierSequenceOffset = publicKeyInfoOffset + getStructuredFieldDataOffset(publicKeyInfoOffset);

  if (getTag(publicAlgorithmIdentifierSequenceOffset) != ASN1_SEQUENCE_TAG)
  {
    LOG_ERROR("Failed to parse the public key algorithm sequence");
    return -1;
  }

  publicAlgorithmIdentifierOffset = publicAlgorithmIdentifierSequenceOffset + getStructuredFieldDataOffset(publicAlgorithmIdentifierSequenceOffset);

  if (getTag(publicAlgorithmIdentifierOffset) != ASN1_OID_TAG)
  {
    LOG_ERROR("Failed to parse the public key algorithm OID");
    return -1;
  }

  tbsCertificate->publicKeyInfo.algorithmOidSize = getField(tbsCertificate->publicKeyInfo.algorithmOid, PUBLIC_KEY_OID_SIZE,
    publicAlgorithmIdentifierOffset, INCLUDE_ZERO_LEADING_BYTES);

  CP_UINT8 rsaBased = 1;
  CP_UINT8 ecdsaBased = 1;
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

  /* loof if it is ECDSA based algorithm */
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
        return -1;
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
        return -1;
    }
  }
  else
  {
    LOG_ERROR("Unrecognized Algorithm");
    tbsCertificate->publicKeyInfo.ePublicKeyInfo = PUBLIC_KEY_INFO_UNRECOGNIZED;
    return -1;
  }

  publicKeyOffset = publicAlgorithmIdentifierSequenceOffset + getNextFieldOffset(publicAlgorithmIdentifierSequenceOffset);

  if (getTag(publicKeyOffset) != ASN1_BIT_STRING_TAG)
  {
    LOG_ERROR("Failed to parse the public key");
    return -1;
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

  return 0;
}

int parseX509SignatureAlgorithm(CP_UINT8 * x509CertSigAlgDerOffset, SignatureAlgorithm * signatureAlgorithm)
{
  CP_UINT8 * sequenceOffset = x509CertSigAlgDerOffset;
  CP_UINT8 * algorithmOidOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);

  if(getTag(algorithmOidOffset) != ASN1_OID_TAG)
  {
    LOG_ERROR("Failed to parse the signature algorithm OID");
    return -1;
  }

  signatureAlgorithm->algorithmOidSize = getField(signatureAlgorithm->algorithmOid, SIGNATURE_ALGORITHM_OID_SIZE,
    algorithmOidOffset, INCLUDE_ZERO_LEADING_BYTES);

  CP_UINT8 rsaBased = 1;
  CP_UINT8 ecdsaBased = 1;
  CP_UINT8 * oidDataOffset = algorithmOidOffset + 2;

  CP_UINT8 count;

  /* look if it is RSA based algorithm */
  for (count = 0; count < RSA_PKCS1_OID_SIZE; count++)
  {
    if (oidDataOffset[count] != RSA_PKCS1_OID[count])
    {
      rsaBased = 0;
    }
  }

  /* loof if it is ECDSA based algorithm */
  if (!rsaBased)
  {
    for (count = 0; count < AINSI_X962_OID_SIZE; count++)
    {
      if (oidDataOffset[count] != AINSI_X962_SIGNATURES_OID[count])
      {
        ecdsaBased = 0;
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
        return -1;
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
        return -1;
        break;
    }
  }
  /* Algorithm Unrecognized */
  else
  {
    LOG_ERROR("Unrecognized signature algorithm");
    signatureAlgorithm->eSigAlg = UNRECOGNIZED_SIGNATURE_ALGORITHM;
    return -1;
  }

  return 0;
}

int parseX509SignatureValue(CP_UINT8 * x509CertSigValDerOffset, SignatureValue * signatureValue)
{
  if(getTag(x509CertSigValDerOffset) != ASN1_BIT_STRING_TAG)
  {
    LOG_ERROR("Failed to parse the signature value");
    return -1;
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

  return 0;
}

int parseX509NameAttributes(CP_UINT8 * x509NameAttributesOffset, NameAttributes * nameAttributes)
{
  CP_UINT8 * endOfNameAttributesOffset = x509NameAttributesOffset + getNextFieldOffset(x509NameAttributesOffset);
  CP_UINT8 * attributeSetOffset = x509NameAttributesOffset + getStructuredFieldDataOffset(x509NameAttributesOffset);

  do
  {
    if (getTag(attributeSetOffset) != ASN1_SET_TAG)
    {
      LOG_ERROR("Failed to parse the attribute set");
      return -1;
    }

    CP_UINT8 * attributeSequenceOffset = attributeSetOffset + getStructuredFieldDataOffset(attributeSetOffset);

    if (getTag(attributeSequenceOffset) != ASN1_SEQUENCE_TAG)
    {
      LOG_ERROR("Failed to parse the attribute sequence");
      return -1;
    }

    CP_UINT8 * attributeOidOffset = attributeSequenceOffset + getStructuredFieldDataOffset(attributeSequenceOffset);

    if (getTag(attributeOidOffset) != ASN1_OID_TAG)
    {
      LOG_ERROR("Failed to parse the attribute OID");
      return -1;
    }

    CP_UINT8 * oidDataOffset = attributeOidOffset + 2;

    CP_UINT8 count;

    for (count = 0; count < ATTRIBUTE_TYPE_OID_SIZE; count++)
    {
      if (oidDataOffset[count] != ATTRIBUTE_TYPE_OID[count])
      {
        LOG_ERROR("Unrecognized attribute OID");
        return -1;
      }
    }

    #if (DBGMSG == 1)
      int i;
    #endif

    CP_UINT8 * attributeDataOffset = attributeOidOffset + getNextFieldOffset(attributeOidOffset);

    switch (oidDataOffset[2])
    {
      case ATTRIBUTE_TYPE_COUNTRY_NAME_OID:

        if (getTag(attributeDataOffset) != ASN1_PRINTABLE_STRING_TAG)
        {
          LOG_ERROR("Failed to parse the country name");
          return -1;
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

  } while((attributeSetOffset += getNextFieldOffset(attributeSetOffset)) != endOfNameAttributesOffset);

  return 0;
}

int parseX509Cert(CP_UINT8 * x509CertDerInput, X509Cert * x509Cert)
{

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
    return -1;
  }
  LOG_INFO("Parsed the sequence");

  /* Parse tbsCertificate */
  tbsCertificateOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
  parseX509TbsCertificate(tbsCertificateOffset, &(x509Cert->tbsCertificate));

  /* Parse the signature algorithm */
  signatureAlgorithmOffset = tbsCertificateOffset + getNextFieldOffset(tbsCertificateOffset);
  parseX509SignatureAlgorithm(signatureAlgorithmOffset, &(x509Cert->signatureAlgorithm));

  /* Parse the signature value */
  signatureValueOffset = signatureAlgorithmOffset + getNextFieldOffset(signatureAlgorithmOffset);
  parseX509SignatureValue(signatureValueOffset, &(x509Cert->signatureValue));

  return 0;
}
