#include "cp_config.h"

#define MAX_ONE_BYTE_LENGTH 0x80
#define MIN_ONE_BYTE_LENGTH 0x00
#define TAG_MASK 0x1F
#define STRUCTURED_FIELD_MASK 0x20
#define ASN1_SEQUENCE_TAG 0x10
#define ASN1_INTEGER_TAG 0x02

#define IGNORE_ZERO_LEADING_BYTES 1
#define INCLUDE_ZERO_LEADING_BYTES 0

//Same as memcpy provided by the C standard library
void CP_memcpy(CP_UINT8 * dest, const CP_UINT8 * src, CP_UINT32 len);

// this function is only for internal usage
static CP_UINT32 getFirstNonZeroByteOffset(CP_UINT8 * input, CP_UINT32 bufferSize);

CP_UINT32 isFieldStructured(CP_UINT8 * input);

CP_UINT32 getStructuredFieldDataOffset(CP_UINT8 * input);

CP_UINT32 getTag(CP_UINT8 * input);

//this function is only for internal usage
static CP_UINT32 getExtendedSizeField(CP_UINT8 * input, CP_UINT32 sizeFieldLength);

CP_UINT32 getNextFieldOffset(CP_UINT8 * input);

CP_UINT32 getField(CP_UINT8 * buffer, CP_UINT32 bufferSize, CP_UINT8 * input, CP_UINT8 ignoreZeroLeadingBytes);
