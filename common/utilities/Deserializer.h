#ifndef DESERIALIZER_H
#define DESERIALIZER_H
#include <iostream>
#include <arpa/inet.h>
#include <cstring>


class Deserializer
{
	public:
		Deserializer(unsigned char*);
		int deserializeInt();
		void deserializeString(char*, int);
		
	private:
		unsigned char* buffer;
		unsigned int offset;

		char deserializeChar();
};
#endif
