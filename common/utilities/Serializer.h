#ifndef SERIALIZER_H
#define SERIALIZER_H
#include <iostream>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>

class Serializer
{
	public:
		Serializer(unsigned char*);
		void serializeInt(int);
		void serializeString(char*, int);
		int getOffset();
		
	private:
		unsigned char* buffer;
		unsigned int offset;

		void serializeChar(char);
};

#endif
