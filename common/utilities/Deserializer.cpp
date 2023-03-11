#include "Deserializer.h"

Deserializer::Deserializer(unsigned char* buffer)
{
	std::cout << "Constructor begin\n";
	this->buffer = buffer;
	offset = 0;
	std::cout << "Constructor end\n";
}

int Deserializer::deserializeInt()
{
/*	std::cout << "deserializeInt begin\n";
	int* network_value_pointer = (int*)(buffer+offset);
	std::cout << "deserializeInt 2\n";
	std::cout << "nvp: " << *network_value_pointer << '\n';
	int tmp = ntohl(*(int*)(buffer+offset));
	std::cout << "deserializeInt end\n";
	offset += sizeof(int);
*/

	char* int_buffer = (char*)calloc(1, sizeof(int));
	for(int i=0; i<sizeof(int); i++)
		int_buffer[i] = buffer[offset+i];

	offset +=sizeof(int);

	int tmp = atoi(int_buffer);
	std::cout << tmp << '\n';
	return tmp;
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
