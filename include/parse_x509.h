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

#ifndef CP_PARSE_X509_H_
#define CP_PARSE_X509_H_

#include "cp_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* x509 */
#define SIGNATURE_ALGORITHM_OID_SIZE 20
#define PUBLIC_KEY_OID_SIZE 20
#define SERIAL_NUMBER_MAX_SIZE 20
#define TIME_STRING_MAX_SIZE 40
#define SIGNATURE_SIZE 513 /* 512 signature size + 1 byte for bit string header */
#define PUBLIC_KEY_MAX_SIZE 540 /* 512 (modulus) + 3 ( public exponent) + 25 (DER encoding overhead) */
#define COUNTRY_NAME_SIZE 2
#define STATE_OR_PROVINCE_NAME_MAX_SIZE 128
#define ORGANIZATION_NAME_MAX_SIZE 64
#define COMMON_NAME_MAX_SIZE 64
#define EMAIL_ADDRESS_MAX_SIZE 64

/* PKCS #1 OID (Needed for RSA)*/
#define RSA_PKCS1_OID_SIZE 8
extern const CP_UINT8 RSA_PKCS1_OID[RSA_PKCS1_OID_SIZE];

/* RSA Signature Algorithms Object Identifiers (OIDs) */
#define RSA_SSA_PKCS_V_1_5_MD2_OID 0x02
#define RSA_SSA_PKCS_V_1_5_MD5_OID 0x04
#define RSA_SSA_PKCS_V_1_5_SHA1_OID 0x05
#define RSA_SSA_PKCS_V_1_5_SHA224_OID 0x0E
#define RSA_SSA_PKCS_V_1_5_SHA256_OID 0x0B
#define RSA_SSA_PKCS_V_1_5_SHA384_OID 0x0C
#define RSA_SSA_PKCS_V_1_5_SHA512_OID 0x0D
#define RSA_SSA_PKCS_V_1_5_SHA_512_224_OID 0x0F
#define RSA_SSA_PKCS_V_1_5_SHA_512_256_OID 0x10
#define RSA_SSA_PSS_OID 0x0A

/* ANSI X9.62 OID (Needed for ECDSA)*/
#define AINSI_X962_OID_SIZE 5
extern const CP_UINT8 AINSI_X962_SIGNATURES_OID[AINSI_X962_OID_SIZE+1];
extern const CP_UINT8 AINSI_X962_PUBLICKEYS_OID[AINSI_X962_OID_SIZE+1];

/* ECDSA Signature Algorithms Object Identifiers (OIDs) */
#define ECDSA_SHA1_OID 0x01
#define ECDSA_SHA2_OID 0x03

/* Thawte OID (Needed for EdDSA Algorithms (ED25519, ED448, etc) )*/
#define THAWTE_OID_SIZE 2
extern const CP_UINT8 THAWTE_OID[THAWTE_OID_SIZE];

/* EdDSA Signature Algorithms Object Identifiers (OIDs) */
#define ED25519_SIGNATURE_ALG_OID 0x70 /* Same OID for the public key and the signature*/
#define ED448_SIGNATURE_ALG_OID 0x71 /* Same OID for the public key and the signature*/

/* Public Keys OIDs */
#define RSA_PUB_KEY_OID 0x01
#define ECDSA_PUB_KEY_OID 0x01
#define ED25519_PUB_KEY_OID 0x70 /* Same OID for the public key and the signature*/
#define ED448_PUB_KEY_OID 0x71 /* Same OID for the public key and the signature*/

/* Attribute Type OID (needed for identifying the subject's and the ussuer's attributes) */
#define ATTRIBUTE_TYPE_OID_SIZE 2
extern const CP_UINT8 ATTRIBUTE_TYPE_OID[ATTRIBUTE_TYPE_OID_SIZE];

/* PKCS9 OID needed for the email attribute*/
#define PKCS_9_OID_SIZE 8
extern const CP_UINT8 PKCS_9_OID[PKCS_9_OID_SIZE];

/* Attributes' types OIDs */
#define ATTRIBUTE_TYPE_NAME_OID 0x29
#define ATTRIBUTE_TYPE_SUR_NAME_OID 0x04
#define ATTRIBUTE_TYPE_GIVEN_NAME_OID 0x2A
#define ATTRIBUTE_TYPE_INITIALS_OID 0x2B
#define ATTRIBUTE_TYPE_GENERATION_QUALIFIER_OID 0x2C
#define ATTRIBUTE_TYPE_COMMON_NAME_OID 0x03
#define ATTRIBUTE_TYPE_LOCALITY_NAME_OID 0x07
#define ATTRIBUTE_TYPE_STATE_OR_PROVINCE_NAME_OID 0x08
#define ATTRIBUTE_TYPE_ORGANIZATION_NAME_OID 0x0A
#define ATTRIBUTE_TYPE_ORGANIZATIONAL_UNIT_NAME_OID 0x0B
#define ATTRIBUTE_TYPE_TITLE_OID 0x0C
#define ATTRIBUTE_TYPE_DN_QUALIFIER_OID 0x2E
#define ATTRIBUTE_TYPE_COUNTRY_NAME_OID 0x06
#define ATTRIBUTE_TYPE_SERIAL_NUMBER_OID 0x05
#define ATTRIBUTE_TYPE_PSEUDONYM_OID 0x41
#define ATTRIBUTE_TYPE_EMAIL_ADDRESS_OID 0x01

/* Certificate Extension OID */
#define CERTIFICATE_EXTENSION_OID_SIZE 2
extern const CP_UINT8 CERTIFICATE_EXTENSION_OID[CERTIFICATE_EXTENSION_OID_SIZE];

/* Extensions OIDs*/
#define EXTENSION_BASIC_CONSTRAINTS_OID 0x13
#define EXTENSION_KEY_USAGE_OID 0x0F

/* x509 Certificate ASN.1 structure from rfc5280

Certificate  ::=  SEQUENCE  {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

   CertificateSerialNumber  ::=  INTEGER

   Validity ::= SEQUENCE {
        notBefore      Time,
        notAfter       Time }

   Time ::= CHOICE {
        utcTime        UTCTime,
        generalTime    GeneralizedTime }

   UniqueIdentifier  ::=  BIT STRING

   SubjectPublicKeyInfo  ::=  SEQUENCE  {
        algorithm            AlgorithmIdentifier,
        subjectPublicKey     BIT STRING  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
        extnID      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                    -- contains the DER encoding of an ASN.1 value
                    -- corresponding to the extension type identified
                    -- by extnID
        }

AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }

*/

typedef enum
{
  RSA_SSA_PKCS_V_1_5_MD2 = 0,
  RSA_SSA_PKCS_V_1_5_MD5,
  RSA_SSA_PKCS_V_1_5_SHA1,
  RSA_SSA_PKCS_V_1_5_SHA224,
  RSA_SSA_PKCS_V_1_5_SHA256,
  RSA_SSA_PKCS_V_1_5_SHA384,
  RSA_SSA_PKCS_V_1_5_SHA512,
  RSA_SSA_PKCS_V_1_5_SHA_512_224,
  RSA_SSA_PKCS_V_1_5_SHA_512_256,
  RSA_SSA_PSS,
  ECDSA_SHA1,
  ECDSA_SHA2,
  ED25519,
  ED448,
  UNRECOGNIZED_SIGNATURE_ALGORITHM
}SignatureAlgorithmEnum;

typedef enum
{
  PUBLIC_KEY_INFO_RSA,
  PUBLIC_KEY_INFO_ECDSA,
  PUBLIC_KEY_INFO_ED25519,
  PUBLIC_KEY_INFO_ED448,
  PUBLIC_KEY_INFO_UNRECOGNIZED
}PublicKeyInfoEnum;

/* Signature Algorithm */
typedef struct
{
  CP_UINT8 algorithmOid[SIGNATURE_ALGORITHM_OID_SIZE];
  CP_UINT8 algorithmOidSize;
  /* TODO Parameters */
  SignatureAlgorithmEnum eSigAlg;
}SignatureAlgorithm;

/* Signature Value */
typedef struct
{
  /* stores the bit string data --> 1 byte header + the signature */
  CP_UINT8 signatureValueBitString[SIGNATURE_SIZE];
  /* points to the signature value --> signatureValueBitString + 1 */
  CP_UINT8 * signatureValue;
  /* the size of the signature */
  CP_UINT16 signatureValueSize;
}SignatureValue;

/* Validity (needed inside TbsCertificate)*/
typedef struct
{
  CP_UINT8 validityNotBefore[TIME_STRING_MAX_SIZE];
  CP_UINT8 isValidityNotBeforeInGenFormat;
  CP_UINT8 validityNotBeforeSize;
  CP_UINT8 validityNotAfter[TIME_STRING_MAX_SIZE];
  CP_UINT8 isValidityNotAfterInGenFormat;
  CP_UINT8 validityNotAfterSize;
}Validity;

/* Subject and issuer attributes */
typedef struct
{
  CP_UINT8 country[COUNTRY_NAME_SIZE];
  CP_UINT8 state[STATE_OR_PROVINCE_NAME_MAX_SIZE];
  CP_UINT8 stateSize;
  CP_UINT8 organization[ORGANIZATION_NAME_MAX_SIZE];
  CP_UINT8 organizationSize;
  CP_UINT8 commonName[COMMON_NAME_MAX_SIZE];
  CP_UINT8 commonNameSize;
  CP_UINT8 emailAddress[EMAIL_ADDRESS_MAX_SIZE];
  CP_UINT8 emailAddressSize;
} NameAttributes;

/* Public key */
typedef struct
{
  CP_UINT8 algorithmOid[PUBLIC_KEY_OID_SIZE];
  CP_UINT8 algorithmOidSize;
  CP_UINT8 publicKeyBitString[PUBLIC_KEY_MAX_SIZE + 1];
  CP_UINT8 * publicKey;
  CP_UINT16 publicKeySize;
  PublicKeyInfoEnum ePublicKeyInfo;
} PublicKeyInfo;

/* Basic Constraints Extension*/
typedef struct
{
  CP_UINT8 isPresent;
  CP_UINT8 isCritical;
  CP_UINT8 ca;
}BasicConstraintsExtension;

/* Key Usage Extension*/
typedef struct
{
  CP_UINT8 isPresent;
  CP_UINT8 isCritical;
  CP_UINT8 digitalSignature;
  CP_UINT8 nonRepudiation;
  CP_UINT8 keyEncipherment;
  CP_UINT8 dataEncipherment;
  CP_UINT8 keyAgreement;
  CP_UINT8 keyCertSign;
  CP_UINT8 cRLSign;
  CP_UINT8 encipherOnly;
  CP_UINT8 decipherOnly;
}KeyUsageExtension;

/* Extension */
typedef struct
{
  //TODO
  BasicConstraintsExtension basicConstraints;
  KeyUsageExtension keyUsage;
  CP_UINT8 numberOfExtensions;
}Extensions;

/* TBSCertificate */
typedef struct
{
  CP_UINT8 version;
  CP_UINT8 serialNumber[SERIAL_NUMBER_MAX_SIZE];
  CP_UINT8 serialNumberSize;
  SignatureAlgorithm signatureAlgorithm;
  NameAttributes issuer;
  Validity validity;
  NameAttributes subject;
  PublicKeyInfo publicKeyInfo;
  Extensions extensions;
}TbsCertificate;

typedef struct
{
  /* TBSCertificate */
  TbsCertificate tbsCertificate;

  /* Signature Algorithm */
  SignatureAlgorithm signatureAlgorithm;

  /* Signature Value */
  SignatureValue signatureValue;

}X509Cert;

/**
 * @brief Parse the TBSCertificate (To Be Signed Certificate) part of the Certificate
 *
 * @param[in] x509TbsCertDerOffset the start offset of the TBSCertificate
 * @param[in,out] tbsCertificate pointer to TbsCertificate that will hold the parsed tbsCertificate
 *
 * @return CP_SUCCESS or CP_ERROR
 */
CPErrorCode parseX509TbsCertificate(CP_UINT8 * x509TbsCertDerOffset, TbsCertificate * tbsCertificate);

/**
 * @brief Parse the Signature Algorithm part of the Certificate
 *
 * @param[in] x509CertSigAlgDerOffset the start offset of the Signature Algorithm
 * @param[in,out] signatureAlgorithm pointer to SignatureAlgorithm that will hold the parsed Signature Algorithm
 *
 * @return CP_SUCCESS or CP_ERROR
 */
CPErrorCode parseX509SignatureAlgorithm(CP_UINT8 * x509CertSigAlgDerOffset, SignatureAlgorithm * signatureAlgorithm);

/**
 * @brief Parse the Signature Value part of the Certificate
 *
 * @param[in] x509CertSigValDerOffset the start offset of the Signature Value
 * @param[in,out] signatureValue pointer to SignatureValue that will hold the parsed Signature Value
 *
 * @return CP_SUCCESS or CP_ERROR
 */
CPErrorCode parseX509SignatureValue(CP_UINT8 * x509CertSigValDerOffset, SignatureValue * signatureValue);

/**
 * @brief Parse the Name Attributes, could be used for both subject and issuer
 *
 * @param[in] x509NameAttributesOffset the start offset of the Name attributes
 * @param[in,out] nameAttributes pointer to NameAttributes that will hold the parsed Name Attributes
 *
 * @return CP_SUCCESS or CP_ERROR
 */
CPErrorCode parseX509NameAttributes(CP_UINT8 * x509NameAttributesOffset, NameAttributes * nameAttributes);

/**
 * @brief Parse the issuerUniqueID, subjectUniqueID and the extensions
 *
 * @param[in] tbsStartOffset the start offset of the tbsCertificate
 * @param[in] extensionsOffset the start offset of the SubjectPublicKeyInfo
 * @param[in,out] extensions pointer to Extensions that will hold the parsed components
 *
 * @return CP_SUCCESS or CP_ERROR
 */
CPErrorCode pareseX509Extensions(CP_UINT8 * tbsCertStartOffset, CP_UINT8 * publicKeyInfoOffset, Extensions * extensions);

/**
 * @brief Parse X.509 Certificate
 *
 * @param[in] x509CertDerInput X.509 Certificate encoded in DER format
 * @param[in,out] x509Cert pointer to X509Cert that will hold the parsed X.509 Certificate
 *
 * @return CP_SUCCESS or CP_ERROR
 */
CPErrorCode parseX509Cert(CP_UINT8 * x509CertDerInput, X509Cert * x509Cert);

#ifdef __cplusplus
}
#endif

#endif
