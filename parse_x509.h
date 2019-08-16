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

/* x509 */
#define SIGNATURE_ALGORITHM_OID_SIZE 20
#define SIGNATURE_SIZE 512

/* PKCS #1 OID (Needed for RSA)*/
#define RSA_PKCS1_OID_SIZE 8
static const CP_UINT8 RSA_PKCS1_OID[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01};

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
static const CP_UINT8 AINSI_X962_SIGNATURES_OID[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04};

/* ECDSA Signature Algorithms Object Identifiers (OIDs) */
#define ECDSA_SHA1_OID 0x01
#define ECDSA_SHA2_OID 0x03

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

/* TODO TBSCertificate
typedef struct
{

}tbsCertificate;
*/

/* Signature Algorithm */
typedef struct
{
  CP_UINT8 algorithmOid[SIGNATURE_ALGORITHM_OID_SIZE];
  CP_UINT8 algorithmOidSize;
  /* TODO Parameters */
}SignatureAlgorithm;


typedef struct
{
  /* TODO TBSCertificate */

  /* Signature Algorithm */
  SignatureAlgorithm signatureAlgorithm;

  /* Signature Value */
  CP_UINT8 signatureValue[SIGNATURE_SIZE];

}X509Cert;

int parseX509SignatureAlgorithm(CP_UINT8 * x509CertSigAlgDerOffset, SignatureAlgorithm * signatureAlgorithm);

int parseX509Cert(CP_UINT8 * x509CertDerInput, X509Cert * x509Cert);
