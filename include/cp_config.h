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

#ifndef CP_CONFIG_H_
#define CP_CONFIG_H_

/******************************************************************************/
/* Configuration                                                              */
/******************************************************************************/

/*
 * Set this MACRO to 1 to use the C's standard library types defined in <stdint.h> (e.g. uint8_t, uint16_t, etc...)
 * Set this MACRO to 0 to use the CP (Crypto Parser) types. This is useful is the C standard library is not available
 * in your system.
 */
#define USE_C_STDLIB_TYPES 0

/*
 * Set this MACRO to 1 to print the logs. (the printf function from the C standard library is used)
 * Set this MACRO to 0 to deactivate the logs.
 */
#define DBGMSG 0

/*
 * Set this MACRO to 1 to enable parsing the x509 extensions
 * Set this MACRO to 0 to disable parsing the x509 extensions
 * Disabling parsing the extensions makes the library and the x509 structure smaller
 * and makes parsing x509 certificates faster
 */
#define ENABLE_X509_EXTENSIONS 1

/*
 * If you decide to not use the types from the C standard library, you must configure the crypto parser types according
 * to your architecture. The configuration below is a default one and may not be suitable for your architecture.
 */
#if (USE_C_STDLIB_TYPES == 0)
  /** 64 bit unsigned integer. */
  typedef unsigned long CP_UINT64;
  /** 64 bit signed integer. */
  typedef signed long CP_SINT64;
  /** 32 bit unsigned integer. */
  typedef unsigned int CP_UINT32;
  /** 16 bit unsigned integer. */
  typedef unsigned short CP_UINT16;
  /** 8 bit unsigned integer. */
  typedef unsigned char CP_UINT8;
  /** 32 bit signed integer. */
  typedef signed int CP_SINT32;
  /** 16 bit signed integer. */
  typedef signed short CP_SINT16;
  /** 8 bit signed integer. */
  typedef signed char CP_SINT8;
#endif
/******************************************************************************/
/* End                                                                        */
/******************************************************************************/


/******************************************************************************/
/* PLEASE DON'T MODIFY!!!!!                                                   */
/******************************************************************************/

#if (USE_C_STDLIB_TYPES == 1)
  #include <stdint.h>
  /** 64 bit unsigned integer typedef */
  typedef uint64_t    CP_UINT64;
  /** 64 bit signed integer typedef */
  typedef int64_t     CP_SINT64;
  /** 32 bit unsigned integer typedef */
  typedef uint32_t    CP_UINT32;
  /** 16 bit unsigned integer typedef */
  typedef uint16_t    CP_UINT16;
  /** 8 bit unsigned integer typedef */
  typedef uint8_t     CP_UINT8;
  /** 32 bit signed integer typedef */
  typedef int32_t     CP_SINT32;
  /** 16 bit signed integer typedef */
  typedef int16_t     CP_SINT16;
  /** 8 bit signed integer typedef */
  typedef int8_t      CP_SINT8;
#endif /* end USE_C_STDLIB_TYPES */

#if (DBGMSG == 1)
  #include <stdio.h>
  #define LOG_INFO(m) printf("[INFO] %s \n", m)
  #define LOG_ERROR(m) printf("[ERROR] %s \n", m)
  #define LOG_WARNING(m) printf("[WARNING] %s \n", m)
#else
  #define LOG_INFO(m)
  #define LOG_ERROR(m)
  #define LOG_WARNING(m)
#endif /* end DBGMSG */

typedef enum
{
  CP_SUCCESS = 0,
  CP_ERROR
}CPErrorCode;

#endif /* end CP_CONFIG_H_ */
