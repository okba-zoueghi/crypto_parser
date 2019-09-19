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
        return -1;

      default:
        break;
    }
  }

  if(!oflag || !fflag || !objectType || !fileName)
  {
    print_usage();
    return -1;
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
    return -1;
  }

  int fd = open (fileName, O_RDONLY);
  int fileSize;
  struct stat fileStat;
  int status = fstat (fd, &fileStat);
  fileSize = fileStat.st_size;

  if(fd < 0)
  {
    printf("Faild to open \"%s\"\n", fileName);
    return -1;
  }

  void * objectData = (char *) mmap (NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);

  if (objectData == MAP_FAILED)
  {
    printf("Failed to map \"%s\"\n", fileName);
    return -1;
  }


  switch (objectIndex)
  {
    case X509CERT_OBJ:
    {
      X509Cert x509Cert;
      parseX509Cert(objectData, &x509Cert);
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

  return 0;
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
