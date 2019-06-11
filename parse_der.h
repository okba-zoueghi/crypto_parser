#include <string.h>

#define MAX_ONE_BYTE_LENGTH 0x80
#define MIN_ONE_BYTE_LENGTH 0x00
#define TAG_MASK 0x1F
#define STRUCTURED_FIELD_MASK 0x20
#define ASN1_SEQUENCE_TAG 0x10
#define ASN1_INTEGER_TAG 0x02

#define IGNORE_ZERO_LEADING_BYTES 1
#define INCLUDE_ZERO_LEADING_BYTES 0

//Same as memcpy provided by the C standard library
void CP_memcpy(unsigned char * dest, const unsigned char * src, unsigned int len);

// this function is only for internal usage
static size_t getFirstNonZeroByteOffset(unsigned char * input, size_t bufferSize);

size_t isFieldStructured(unsigned char * input);

size_t getStructuredFieldDataOffset(unsigned char * input);

size_t getTag(unsigned char * input);

//this function is only for internal usage
static size_t getExtendedSizeField(unsigned char * input, size_t sizeFieldLength);

size_t getNextFieldOffset(unsigned char * input);

size_t getField(unsigned char * buffer, size_t bufferSize, unsigned char * input, unsigned char ignoreZeroLeadingBytes);
