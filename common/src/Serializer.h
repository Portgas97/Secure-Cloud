#ifndef SERIALIZER_H
#define SERIALIZER_H
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <openssl/bio.h>


class Serializer
{
	public:
		Serializer(unsigned char*);
		void serializeInt(int);
		void serializeString(char*, unsigned int);
		void serializeByteStream(unsigned char*, unsigned int);
		void serializeChar(char);
		int getOffset();
		
	private:
		unsigned char* buffer;
		unsigned int offset;
};

#endif
