#ifndef CP_CONFIG_H_
#define CP_CONFIG_H_

/******************************************************************************/
/* Configuration                                                              */
/******************************************************************************/

/*
 * Set this MACRO to 1 to use the C's standard library types defined in <stdint.h> (e.g. uint8_t, uint16_t, etc...)
 * Set this MACRO to 0 to use the CP (Crypto Parser types). This is useful is the C standard library could not be used.
 */
#define USE_C_STDLIB_TYPES 0

/*
 * Set this MACRO to 1 to print the logs. (the printf function from the C standard library is used)
 * Set this MACRO to 0 to deactivate the logs.
 */
#define DBGMSG 0

/******************************************************************************/
/* End                                                                        */
/******************************************************************************/


/******************************************************************************/
/* PLEASE DON'T MODIFY!!!!!                                                   */
/******************************************************************************/

#if USE_C_STDLIB_TYPES == 1
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
#else
  /** 64 bit unsigned integer. */
  typedef unsigned long long CP_UINT64;
  /** 64 bit signed integer. */
  typedef signed long long CP_SINT64;
  /** 32 bit unsigned integer. */
  typedef unsigned long CP_UINT32;
  /** 16 bit unsigned integer. */
  typedef unsigned short CP_UINT16;
  /** 8 bit unsigned integer. */
  typedef unsigned char CP_UINT8;
  /** 32 bit signed integer. */
  typedef signed long CP_SINT32;
  /** 16 bit signed integer. */
  typedef signed short CP_SINT16;
  /** 8 bit signed integer. */
  typedef signed char CP_SINT8;
#endif /* end USE_C_STDLIB_TYPES */

#if DBGMSG == 1
  #include <stdio.h>
  #define LOG_INFO(m) printf("[INFO] %s \n", m)
  #define LOG_ERROR(m) printf("[ERROR] %s \n", m)
#else
  #define LOG_INFO(m)
  #define LOG_ERROR(m)
#endif /* end DBGMSG */

#endif /* end CP_CONFIG_H_ */
