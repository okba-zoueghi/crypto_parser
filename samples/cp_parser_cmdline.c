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

/* C standard library */
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

/* crypto parser headers */
#include "parse_dhparam.h"
#include "parse_dsa.h"
#include "parse_rsa.h"
#include "parse_x509.h"

typedef enum
{
  X509CERT_OBJ = 0,
  RSA_PUBLIC_KEY_OBJ,
  RSA_PRIVATE_KEY_OBJ,
  DH_PARAM_OBJ,
  DSA_PARAM_OBJ,
}ObjectType;

void print_usage(void);

void printX509(X509Cert * x509Cert);

int main(int argc, char **argv)
{

  char oflag = 0, fflag = 0;
  char * objectType = NULL;
  char * fileName = NULL;
  int arg;

  while ( (arg = getopt(argc, argv, "o:f:")) != -1 )
  {
    switch (arg)
    {
      case 'o':
        oflag = 1;
        objectType = optarg;
        break;

      case 'f':
        fflag = 1;
        fileName = optarg;
        break;

      case '?':
        print_usage();
        return CP_ERROR;

      default:
        break;
    }
  }

  if(!oflag || !fflag || !objectType || !fileName)
  {
    print_usage();
    return CP_ERROR;
  }

  const char * objectTypes[] = { "x509Cert", "rsaPubKey", "rsaPrivKey", "dhParam", "dsaParam"};
  ObjectType objectIndex = -1;
  int i;

  for (i = 0; i < 5; i++)
  {
    if(strcmp(objectTypes[i], objectType) == 0)
      objectIndex = i;
  }

  if (objectIndex == -1)
  {
    print_usage();
    return CP_ERROR;
  }

  int fd = open (fileName, O_RDONLY);
  int fileSize;
  struct stat fileStat;

  int status = fstat (fd, &fileStat);

  if (status != 0)
  {
    printf("Faild to get the file size\n");
    return CP_ERROR;
  }

  fileSize = fileStat.st_size;

  if(fd < 0)
  {
    printf("Faild to open \"%s\"\n", fileName);
    return CP_ERROR;
  }

  void * objectData = (char *) mmap (NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);

  if (objectData == MAP_FAILED)
  {
    printf("Failed to map \"%s\"\n", fileName);
    return CP_ERROR;
  }


  switch (objectIndex)
  {
    case X509CERT_OBJ:
    {
      X509Cert x509Cert;
      parseX509Cert(objectData, &x509Cert);
      printX509(&x509Cert);
      break;
    }

    case RSA_PUBLIC_KEY_OBJ:
    {
      RsaPublicKey rsaPublicKey;
      parseRsaPublicKey(objectData, &rsaPublicKey, PKCS_1);
      break;
    }

    case RSA_PRIVATE_KEY_OBJ:
    {
      RsaPrivateKey rsaPrivateKey;
      parseRsaPrivateKey(objectData, &rsaPrivateKey);
      break;
    }

    case DH_PARAM_OBJ:
    {
      DhParam dhParam;
      parseDhParam(objectData, &dhParam);
      break;
    }

    case DSA_PARAM_OBJ:
    {
      DsaParam dsaParam;
      parseDsaParam(objectData, &dsaParam);
      break;
    }

  }

  munmap(objectData, fileSize);
  close(fd);

  return CP_SUCCESS;
}

void print_usage(void)
{
  char * usage =
    "usage:\n\n"\
    "crypto_parser -o <x509Cert|rsaPubKey|rsaPrivKey|dhParam|dsaParam> -f <file.der>\n\n"\
    "-o   specify the crypto object type, it could be one of the following values\n"\
    "     x509Cert|rsaPubKey|rsaPrivKey|dhParam|dsaParam\n\n"\
    "-f   specify the file to parse in DER format\n";
  printf("%s\n", usage);
}

void printX509(X509Cert * x509Cert)
{
  int i = 0;

  printf("Certificate:\n");

  printf("\t Version:\n");
  printf("\t\t %d\n", x509Cert->tbsCertificate.version);

  printf("\t Serial Number:\n");
  printf("\t\t ");
  for (i = 0; i < x509Cert->tbsCertificate.serialNumberSize; i++)
  {
    if( (i > 0) && ((i % 20) == 0) )
      printf("\n\t\t\t ");
    printf("%02X:",x509Cert->tbsCertificate.serialNumber[i]);
  }
  printf("\n");

  printf("\t Signature Algorithm:\n");
  printf("\t\t ");
  switch (x509Cert->tbsCertificate.signatureAlgorithm.eSigAlg)
  {
    case RSA_SSA_PKCS_V_1_5_MD2 :
      printf("RSA_SSA_PKCS_V_1_5_MD2\n");
      break;
    case RSA_SSA_PKCS_V_1_5_MD5 :
      printf("RSA_SSA_PKCS_V_1_5_MD5\n");
      break;
    case RSA_SSA_PKCS_V_1_5_SHA1 :
      printf("RSA_SSA_PKCS_V_1_5_SHA1\n");
      break;
    case RSA_SSA_PKCS_V_1_5_SHA224 :
      printf("RSA_SSA_PKCS_V_1_5_SHA224\n");
      break;
    case RSA_SSA_PKCS_V_1_5_SHA256 :
      printf("RSA_SSA_PKCS_V_1_5_SHA256\n");
      break;
    case RSA_SSA_PKCS_V_1_5_SHA384 :
      printf("RSA_SSA_PKCS_V_1_5_SHA384\n");
      break;
    case RSA_SSA_PKCS_V_1_5_SHA512 :
      printf("RSA_SSA_PKCS_V_1_5_SHA512\n");
      break;
    case RSA_SSA_PKCS_V_1_5_SHA_512_224 :
      printf("RSA_SSA_PKCS_V_1_5_SHA_512_224\n");
      break;
    case RSA_SSA_PKCS_V_1_5_SHA_512_256 :
      printf("RSA_SSA_PKCS_V_1_5_SHA_512_256\n");
      break;
    case RSA_SSA_PSS :
      printf("RSA_SSA_PSS\n");
      break;
    case ECDSA_SHA1 :
      printf("ECDSA_SHA1\n");
      break;
    case ECDSA_SHA2 :
      printf("ECDSA_SHA2\n");
      break;
    default:
      printf("Unknown\n");
      break;
  }

  printf("\t Issuer:\n");
  printf("\t\t Country (C) : ");
  for (i = 0; i < 2; i++)
  {
    printf("%c",x509Cert->tbsCertificate.issuer.country[i]);
  }
  printf("\n");
  printf("\t\t State or Province (ST) : ");
  for (i = 0; i < x509Cert->tbsCertificate.issuer.stateSize; i++)
  {
    printf("%c",x509Cert->tbsCertificate.issuer.state[i]);
  }
  printf("\n");
  printf("\t\t Organization (O) : ");
  for (i = 0; i < x509Cert->tbsCertificate.issuer.organizationSize; i++)
  {
    printf("%c",x509Cert->tbsCertificate.issuer.organization[i]);
  }
  printf("\n");
  printf("\t\t Common Name (CN) : ");
  for (i = 0; i < x509Cert->tbsCertificate.issuer.commonNameSize; i++)
  {
    printf("%c",x509Cert->tbsCertificate.issuer.commonName[i]);
  }
  printf("\n");

  printf("\t Validity:\n");
  printf("\t\t Not Valid before : ");
  switch (x509Cert->tbsCertificate.validity.isValidityNotBeforeInGenFormat)
  {
    case 1:
      printf("%c%c%c%c/%c%c/%c%c\n",
        x509Cert->tbsCertificate.validity.validityNotBefore[0],
        x509Cert->tbsCertificate.validity.validityNotBefore[1],
        x509Cert->tbsCertificate.validity.validityNotBefore[2],
        x509Cert->tbsCertificate.validity.validityNotBefore[3],
        x509Cert->tbsCertificate.validity.validityNotBefore[4],
        x509Cert->tbsCertificate.validity.validityNotBefore[5],
        x509Cert->tbsCertificate.validity.validityNotBefore[6],
        x509Cert->tbsCertificate.validity.validityNotBefore[7]);
      break;
    case 0:
      printf("20%c%c/%c%c/%c%c\n",
        x509Cert->tbsCertificate.validity.validityNotBefore[0],
        x509Cert->tbsCertificate.validity.validityNotBefore[1],
        x509Cert->tbsCertificate.validity.validityNotBefore[2],
        x509Cert->tbsCertificate.validity.validityNotBefore[3],
        x509Cert->tbsCertificate.validity.validityNotBefore[4],
        x509Cert->tbsCertificate.validity.validityNotBefore[5]);
      break;

    default:
      break;
  }
  printf("\t\t Not Valid After : ");
  switch (x509Cert->tbsCertificate.validity.isValidityNotAfterInGenFormat)
  {
    case 1:
      printf("%c%c%c%c/%c%c/%c%c\n",
        x509Cert->tbsCertificate.validity.validityNotAfter[0],
        x509Cert->tbsCertificate.validity.validityNotAfter[1],
        x509Cert->tbsCertificate.validity.validityNotAfter[2],
        x509Cert->tbsCertificate.validity.validityNotAfter[3],
        x509Cert->tbsCertificate.validity.validityNotAfter[4],
        x509Cert->tbsCertificate.validity.validityNotAfter[5],
        x509Cert->tbsCertificate.validity.validityNotAfter[6],
        x509Cert->tbsCertificate.validity.validityNotAfter[7]);
      break;
    case 0:
      printf("20%c%c/%c%c/%c%c\n",
        x509Cert->tbsCertificate.validity.validityNotAfter[0],
        x509Cert->tbsCertificate.validity.validityNotAfter[1],
        x509Cert->tbsCertificate.validity.validityNotAfter[2],
        x509Cert->tbsCertificate.validity.validityNotAfter[3],
        x509Cert->tbsCertificate.validity.validityNotAfter[4],
        x509Cert->tbsCertificate.validity.validityNotAfter[5]);
      break;

    default:
      break;
  }

  printf("\t Subject:\n");
  printf("\t\t Country (C) : ");
  for (i = 0; i < 2; i++)
  {
    printf("%c",x509Cert->tbsCertificate.subject.country[i]);
  }
  printf("\n");
  printf("\t\t State or Province (ST) : ");
  for (i = 0; i < x509Cert->tbsCertificate.subject.stateSize; i++)
  {
    printf("%c",x509Cert->tbsCertificate.subject.state[i]);
  }
  printf("\n");
  printf("\t\t Organization (O) : ");
  for (i = 0; i < x509Cert->tbsCertificate.subject.organizationSize; i++)
  {
    printf("%c",x509Cert->tbsCertificate.subject.organization[i]);
  }
  printf("\n");
  printf("\t\t Common Name (CN) : ");
  for (i = 0; i < x509Cert->tbsCertificate.subject.commonNameSize; i++)
  {
    printf("%c",x509Cert->tbsCertificate.subject.commonName[i]);
  }
  printf("\n");

  printf("\t Public Key Algorithm: ");
  switch (x509Cert->tbsCertificate.publicKeyInfo.ePublicKeyInfo)
  {
    case PUBLIC_KEY_INFO_RSA:
      printf("RSA\n");
      break;
    case PUBLIC_KEY_INFO_ECDSA:
      printf("ECDSA\n");
      break;
    default:
      printf("Unknown\n");
      break;
  }
  printf("\t\t ");
  for (i = 0; i < x509Cert->tbsCertificate.publicKeyInfo.publicKeySize; i++)
  {
    if( (i > 0) && ((i % 20) == 0) )
      printf("\n\t\t ");
    printf("%02X:",x509Cert->tbsCertificate.publicKeyInfo.publicKey[i]);
  }
  printf("\n");

  printf("\t Signature:\n");
  printf("\t\t ");
  for (i = 0; i < x509Cert->signatureValue.signatureValueSize; i++)
  {
    if( (i > 0) && ((i % 20) == 0) )
      printf("\n\t\t ");
    printf("%02X:",x509Cert->signatureValue.signatureValue[i]);
  }
  printf("\n");

}
