#include "Serializer.h"


Serializer::Serializer(unsigned char* buffer)
{
	this->buffer = buffer;
	offset = 0;
}

void Serializer::serializeInt(int value)
{
	int *network_value_pointer = (int*)calloc(1,sizeof(1));
	
	if(network_value_pointer == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	*network_value_pointer = htonl(value);
	memcpy(buffer+offset, network_value_pointer, sizeof(int));
	offset += sizeof(int);	
}

void Serializer::serializeChar(char value)
{
	buffer[offset++] = value;
}

void Serializer::serializeString(char* string, int string_size)
{
	for(int i=0; i<string_size; i++)
		serializeChar(string[i]);	
}

int Serializer::getOffset()
{
	return offset;
}
