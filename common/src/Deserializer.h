#ifndef DESERIALIZER_H
#define DESERIALIZER_H
#include <cstring>
#include <iostream>
#include <arpa/inet.h>


class Deserializer
{
	public:
		Deserializer(unsigned char*);
		int deserializeInt();
		char deserializeChar();
		void deserializeString(char*, unsigned int);
		void deserializeByteStream(unsigned char*, unsigned int);
		
	private:
		unsigned char* buffer;
		unsigned int offset;

};

#endif
