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
		std::cout << "Error in calloc\n";
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

void Serializer::serializeString(char* string, unsigned int string_size)
{
	for(int i=0; i<string_size; i++)
		serializeChar(string[i]);	
}

void Serializer::serializeByteStream(unsigned char* byte_stream, 
									unsigned int byte_stream_size)
{
	memcpy(buffer+offset, byte_stream, byte_stream_size);
	offset += byte_stream_size;
}									

int Serializer::getOffset()
{
	return offset;
}
