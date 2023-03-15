#ifndef SERIALIZER_H
#define SERIALIZER_H
#include <iostream>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <openssl/bio.h>

class Serializer
{
	public:
		Serializer(unsigned char*);
		void serializeInt(int);
		void serializeString(char*, unsigned int);
		void serializeByteStream(unsigned char*, unsigned int);
		int getOffset();
		
	private:
		unsigned char* buffer;
		unsigned int offset;

		void serializeChar(char);
};

#endif
