#include "Deserializer.h"

Deserializer::Deserializer(unsigned char* buffer)
{
	this->buffer = buffer;
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

	return host_int;

}

char Deserializer::deserializeChar()
{
	return buffer[offset++];
}

void Deserializer::deserializeString(char* string, int string_size)
{
	for(int i=0; i<string_size; i++)
		string[i] = deserializeChar();	
}
