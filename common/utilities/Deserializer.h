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
		void deserializeString(char*, unsigned int);
		void deserializeByteStream(unsigned char*, unsigned int);
		
	private:
		unsigned char* buffer;
		unsigned int offset;

		char deserializeChar();
};
#endif
