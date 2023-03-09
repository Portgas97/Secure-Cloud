#include "Serializer.h"


Serializer::Serializer(unsigned char* buffer)
{
	this->buffer = buffer;
	offset = 0;
}

void Serializer::serializeInt(int value)
{
	int *network_value_ptr = nullptr;
	*network_value_ptr = htonl(value);
	std::memcpy(buffer, network_value_ptr, sizeof(int));
	offset += 4;	
}

void Serializer::serializeChar(char value)
{
	buffer[offset++] = value;
}

void Serializer::serializeString(char* string, int string_size)
{
	for(int i=0; i<string_size; i++)
		serializeChar(buffer+i,string[i]);	

	offset += string_size;
}
