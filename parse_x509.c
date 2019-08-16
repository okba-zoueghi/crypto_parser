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
        break;
      case RSA_SSA_PKCS_V_1_5_MD5_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_MD5");
        break;
      case RSA_SSA_PKCS_V_1_5_SHA1_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA1");
        break;
      case RSA_SSA_PKCS_V_1_5_SHA224_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA224");
        break;
      case RSA_SSA_PKCS_V_1_5_SHA256_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA256");
        break;
      case RSA_SSA_PKCS_V_1_5_SHA384_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA384");
        break;
      case RSA_SSA_PKCS_V_1_5_SHA512_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA512");
        break;
      case RSA_SSA_PKCS_V_1_5_SHA_512_224_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA_512_224");
        break;
      case RSA_SSA_PKCS_V_1_5_SHA_512_256_OID:
        LOG_INFO("SignatureAlgorithm : RSA_SSA_PKCS_V_1_5_SHA_512_256");
        break;
      case RSA_SSA_PSS_OID:
        LOG_INFO("RSA_SSA_PSS");
        break;

      default:
        LOG_ERROR("Unrecognized signature algorithm");
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
        break;
      case ECDSA_SHA2_OID:
        LOG_INFO("SignatureAlgorithm : ECDSA_SHA2");
        break;

      default:
        LOG_ERROR("Unrecognized signature algorithm");
        return -1;
        break;
    }
  }
  /* Algorithm Unrecognized */
  else
  {
    LOG_ERROR("Unrecognized signature algorithm");
    return -1;
  }

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

  tbsCertificateOffset = sequenceOffset + getStructuredFieldDataOffset(sequenceOffset);
  /* TODO Parse tbsCertificate */

  signatureAlgorithmOffset = tbsCertificateOffset + getNextFieldOffset(tbsCertificateOffset);
  parseX509SignatureAlgorithm(signatureAlgorithmOffset, &(x509Cert->signatureAlgorithm));

  return 0;
}
