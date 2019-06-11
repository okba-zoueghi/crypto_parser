#include "parse_der.h"

#include <string.h>
#include <stdint.h>

void CP_memcpy(unsigned char * dest, const unsigned char * src, unsigned int len)
{
  unsigned int i;

  for(i = 0; i < len; i++)
  {
    dest[i] = src[i];
  }

}

static size_t getFirstNonZeroByteOffset(unsigned char * input, size_t inputSize)
{
  size_t countZeroBytes = 0;

  while (!input[countZeroBytes] && (countZeroBytes < inputSize) )
    countZeroBytes++;

  return countZeroBytes;
}

size_t isFieldStructured(unsigned char * input)
{
  size_t isStructured = input[0] & STRUCTURED_FIELD_MASK;
  return isStructured;
}

size_t getStructuredFieldDataOffset(unsigned char * input)
{
  size_t startOffset;
  unsigned char dataSize = input[1];
  //The seqence size field is only one byte
  if(dataSize > MIN_ONE_BYTE_LENGTH && dataSize < MAX_ONE_BYTE_LENGTH)
  {
    startOffset = 2U; //2U --> 1 byte for the tag + 1 byte for the size field
  }
  //The seqence size field is more than one byte
  else
  {
    size_t sizeFieldLength = dataSize - 0x80; // the length of the size field
    startOffset = 2U + sizeFieldLength; // 2U --> 1 byte for the tag + 1 byte for the size field
  }

  return startOffset;
}

size_t getTag(unsigned char * input)
{
  // input[0] --> 2 bits for the class | 1 bit to specify if the type is structured or primitive | 5 bits for the tag
  // TAG_MASK --> define as 0x1F --> 00011111 : mask to get the tag value
  size_t tag = input[0] & TAG_MASK;
  return tag;
}

static size_t getExtendedSizeField(unsigned char * input, size_t sizeFieldLength)
{
  size_t dataSize = 0;
  int shiftValue; // Indicates how many times the byte has to be shifted
  size_t byteIndex; // Indicates the byte index

  for (shiftValue = sizeFieldLength - 1, byteIndex = 0; shiftValue >= 0 ; shiftValue--, byteIndex++)
  {
    dataSize += input[ 2 + byteIndex] << (8 * shiftValue);
  }

  return dataSize;
}

size_t getNextFieldOffset(unsigned char * input)
{
  size_t nextFieldOffset;
  size_t dataSize = input[1];
  //The size field is only one byte
  if(dataSize > MIN_ONE_BYTE_LENGTH && dataSize < MAX_ONE_BYTE_LENGTH)
  {
    nextFieldOffset = 2U + dataSize; // 2U --> 1 byte for the tag + 1 byte for the size field | dataSize -> the size of the data
  }
  //The size field is more than one byte
  else
  {
    size_t sizeFieldLength = dataSize - 0x80; // the length of the size field
    dataSize = getExtendedSizeField(input, sizeFieldLength);

    // 2U --> 1 byte for the tag + 1 byte for the size field
    // sizeFieldLength --> the size of the extension of the size field
    // dataSize --> the data size
    nextFieldOffset = 2U + sizeFieldLength + dataSize;
  }

  return nextFieldOffset;
}

size_t getField(unsigned char * buffer, size_t bufferSize, unsigned char * input, unsigned char ignoreZeroLeadingBytes)
{
  size_t dataSize = input[1];
  size_t dataOffset;
  if(dataSize > MIN_ONE_BYTE_LENGTH && dataSize < MAX_ONE_BYTE_LENGTH)
  {
    dataOffset = 2U; // 2U --> 1 byte for the tag + 1 byte for the size field

    if (ignoreZeroLeadingBytes == IGNORE_ZERO_LEADING_BYTES && dataSize > 1)
    {
      size_t countZeroBytes = getFirstNonZeroByteOffset(input + dataOffset, dataSize);
      dataOffset += countZeroBytes;
      dataSize -= countZeroBytes;
    }

    CP_memcpy(buffer, input + dataOffset, dataSize);
  }
  else
  {
    size_t sizeFieldLength = dataSize - 0x80; // the length of the size field
    dataSize = getExtendedSizeField(input, sizeFieldLength);

    dataOffset = 2U + sizeFieldLength;

    if (ignoreZeroLeadingBytes == IGNORE_ZERO_LEADING_BYTES)
    {
      size_t countZeroBytes = getFirstNonZeroByteOffset(input + dataOffset, dataSize);
      dataOffset += countZeroBytes;
      dataSize -= countZeroBytes;
    }

    CP_memcpy(buffer, input + dataOffset, dataSize);
  }

  return dataSize;
}
