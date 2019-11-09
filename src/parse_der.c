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

void CP_memcpy(CP_UINT8 * dest, const CP_UINT8 * src, CP_UINT32 len)
{
  CP_UINT32 i;

  for(i = 0; i < len; i++)
  {
    dest[i] = src[i];
  }

}

static CP_UINT32 getFirstNonZeroByteOffset(CP_UINT8 * input, CP_UINT32 inputSize)
{
  CP_UINT32 countZeroBytes = 0;

  while (!input[countZeroBytes] && (countZeroBytes < inputSize) )
    countZeroBytes++;

  return countZeroBytes;
}

CP_UINT32 isFieldStructured(CP_UINT8 * input)
{
  CP_UINT32 isStructured = input[0] & STRUCTURED_FIELD_MASK;
  return isStructured;
}

CP_UINT32 getStructuredFieldDataOffset(CP_UINT8 * input)
{
  CP_UINT32 startOffset;
  CP_UINT8 dataSize = input[1];
  //The seqence size field is only one byte
  if(dataSize > MIN_ONE_BYTE_LENGTH && dataSize < MAX_ONE_BYTE_LENGTH)
  {
    startOffset = 2U; //2U --> 1 byte for the tag + 1 byte for the size field
  }
  //The seqence size field is more than one byte
  else
  {
    CP_UINT32 sizeFieldLength = dataSize - 0x80; // the length of the size field
    startOffset = 2U + sizeFieldLength; // 2U --> 1 byte for the tag + 1 byte for the size field
  }

  return startOffset;
}

CP_UINT8 getClass(CP_UINT8 * input)
{
  // input[0] --> 2 bits for the class | 1 bit to specify if the type is structured or primitive | 5 bits for the tag
  // TAG_MASK --> define as 0x1F --> 00011111 : mask to get the tag value
  CP_UINT8 DerClass = input[0] & CLASS_MASK;
  return DerClass;
}

CP_UINT32 getTag(CP_UINT8 * input)
{
  // input[0] --> 2 bits for the class | 1 bit to specify if the type is structured or primitive | 5 bits for the tag
  // TAG_MASK --> define as 0x1F --> 00011111 : mask to get the tag value
  CP_UINT32 tag = input[0] & TAG_MASK;
  return tag;
}

static CP_UINT32 getExtendedSizeField(CP_UINT8 * input, CP_UINT32 sizeFieldLength)
{
  CP_UINT32 dataSize = 0;
  int shiftValue; // Indicates how many times the byte has to be shifted
  CP_UINT32 byteIndex; // Indicates the byte index

  for (shiftValue = sizeFieldLength - 1, byteIndex = 0; shiftValue >= 0 ; shiftValue--, byteIndex++)
  {
    dataSize += input[ 2 + byteIndex] << (8 * shiftValue);
  }

  return dataSize;
}

CP_UINT32 getNextFieldOffset(CP_UINT8 * input)
{
  CP_UINT32 nextFieldOffset;
  CP_UINT32 dataSize = input[1];
  //The size field is only one byte
  if(dataSize > MIN_ONE_BYTE_LENGTH && dataSize < MAX_ONE_BYTE_LENGTH)
  {
    nextFieldOffset = 2U + dataSize; // 2U --> 1 byte for the tag + 1 byte for the size field | dataSize -> the size of the data
  }
  //The size field is more than one byte
  else
  {
    CP_UINT32 sizeFieldLength = dataSize - 0x80; // the length of the size field
    dataSize = getExtendedSizeField(input, sizeFieldLength);

    // 2U --> 1 byte for the tag + 1 byte for the size field
    // sizeFieldLength --> the size of the extension of the size field
    // dataSize --> the data size
    nextFieldOffset = 2U + sizeFieldLength + dataSize;
  }

  return nextFieldOffset;
}

CP_UINT32 getField(CP_UINT8 * buffer, CP_UINT32 bufferSize, CP_UINT8 * input, CP_UINT8 ignoreZeroLeadingBytes)
{
  CP_UINT32 dataSize = input[1];
  CP_UINT32 dataOffset;
  if(dataSize > MIN_ONE_BYTE_LENGTH && dataSize < MAX_ONE_BYTE_LENGTH)
  {
    dataOffset = 2U; // 2U --> 1 byte for the tag + 1 byte for the size field

    if (ignoreZeroLeadingBytes == IGNORE_ZERO_LEADING_BYTES && dataSize > 1)
    {
      CP_UINT32 countZeroBytes = getFirstNonZeroByteOffset(input + dataOffset, dataSize);
      dataOffset += countZeroBytes;
      dataSize -= countZeroBytes;
    }

    CP_memcpy(buffer, input + dataOffset, dataSize);
  }
  else
  {
    CP_UINT32 sizeFieldLength = dataSize - 0x80; // the length of the size field
    dataSize = getExtendedSizeField(input, sizeFieldLength);

    dataOffset = 2U + sizeFieldLength;

    if (ignoreZeroLeadingBytes == IGNORE_ZERO_LEADING_BYTES)
    {
      CP_UINT32 countZeroBytes = getFirstNonZeroByteOffset(input + dataOffset, dataSize);
      dataOffset += countZeroBytes;
      dataSize -= countZeroBytes;
    }

    CP_memcpy(buffer, input + dataOffset, dataSize);
  }

  return dataSize;
}
