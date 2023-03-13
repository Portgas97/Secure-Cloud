#include "Deserializer.h"
#include <cstring>

Deserializer::Deserializer(unsigned char* buffer)
{
	// std::cout << "Constructor begin\n";
	this->buffer = (unsigned char*) calloc(1, 1024); // TO DO ??
	this->buffer = buffer;
	// std::cout << "Passed buffer: ";
	// std::cout << buffer << std::endl;
	// std::cout << "Constructor buffer: ";
	// std::cout << this->buffer << std::endl;
	offset = 0;
	//std::cout << "Constructor end\n";
}

int Deserializer::deserializeInt()
{
	std::cout << "deserializeInt begin\n";

	int* network_value_pointer = (int*)calloc(1, sizeof(int));
	memcpy(network_value_pointer, buffer+offset, sizeof(int));
	int host_int = ntohl(*network_value_pointer);
	std::cout << host_int << std::endl;

	// std::cout << "deserializeInt 2\n";
	// std::cout << "nvp: " << *network_value_pointer << std::endl;
	// int tmp = ntohl(*(int*)(buffer+offset));
	// std::cout << tmp << std::endl;

	std::cout << "deserializeInt end\n";
	offset += sizeof(int);

	return host_int;

/*
	char* int_buffer = (char*)calloc(1, sizeof(int));
	for(int i=0; i<sizeof(int); i++)
		int_buffer[i] = buffer[offset+i];

	offset +=sizeof(int);

	int tmp = atoi(int_buffer);
	std::cout << tmp << '\n';
	return tmp;
*/
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
