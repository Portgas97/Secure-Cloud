#include "Deserializer.h"

Deserializer::Deserializer(unsigned char* buffer)
{
	this->buffer = buffer;
	offset = 0;
}

int Deserializer::serializeInt()
{
	// write big-endian int value into buffer
	// assumes 32-bit int and 8-bit char
	/*buffer[offset++] = value >> 24;
  	buffer[offset++] = value >> 16;
  	buffer[offset++] = value >> 8;
  	buffer[offset++] = value;*/

	
}

void Deserializer::serializeChar(char value)
{
	buffer[offset++] = value;
}

void Deserializer::serializeString(char* string, int string_size)
{
	for(int i=0; i<string_size; i++)
		serializeChar(buffer+i,string[i]);	

	offset += string_size;
}
