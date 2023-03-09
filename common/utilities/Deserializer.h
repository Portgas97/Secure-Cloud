#include <iostream>


class Deserializer
{
	public:
		Deserializer(unsigned char*);
		int deserializeInt();
		unsigned char* deserializeString(int);
		
	private:
		unsigned char* buffer;
		unsigned int offset;

		char deserializeChar();
};
