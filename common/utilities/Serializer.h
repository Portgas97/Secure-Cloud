#include <iostream>
#include <arpa/inet.h>
#include <cstdlilb>



class Serializer
{
	public:
		Serializer(unsigned char*);
		void serializeInt(int);
		void serializeString(char*, int);
		
	private:
		unsigned char* buffer;
		unsigned int offset;

		void serializeChar(char);
};
