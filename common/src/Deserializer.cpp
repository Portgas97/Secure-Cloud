#include "Deserializer.h"
#include "ConnectionManager.h"


Deserializer::Deserializer(unsigned char* buffer_to_deserialize)
{
	buffer = buffer_to_deserialize;
	offset = 0;
}

int Deserializer::deserializeInt()
{
	int* network_value_pointer = (int*)calloc(1, sizeof(int));
	if(network_value_pointer == nullptr)
	{
		std::cout << "Error in calloc" << std::endl;
		exit(1);
	}

	memcpy(network_value_pointer, buffer+offset, sizeof(int));
	int host_int = ntohl(*network_value_pointer);

	offset += sizeof(int);

	free(network_value_pointer);
	
	return host_int;
}


char Deserializer::deserializeChar()
{
	return buffer[offset++];
}


void Deserializer::deserializeString(char* string, unsigned int string_size)
{
	for(unsigned int i=0; i<string_size; i++)
		string[i] = deserializeChar();	
}


void Deserializer::deserializeByteStream(unsigned char* byte_stream,
												unsigned int byte_stream_size)
{
	memcpy(byte_stream, buffer + offset, byte_stream_size);
	offset += byte_stream_size;
}
									
