#ifndef UTILITY_MANAGER_H
#define UTILITY_MANAGER_H

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <limits.h> // required for realpath()
#include <stdlib.h> // required for realpath()
#include <experimental/filesystem>
#include <fstream>
#include <regex>
#include "CryptographyManager.h"
#include "Serializer.h"
#include "Deserializer.h"


class UtilityManager
{
	public:
		static bool isUserPresent(std::string, std::string);
		static std::string getFilename(std::string);
		static unsigned char* getCertificateFromFile(const char*, 
													unsigned int&);
		static unsigned char* getSmallFileContent(FILE* file, unsigned int);
		static std::string getDirectoryFilenames(std::string);
        static void printBuffer(unsigned char*, unsigned int);
		static unsigned int areBuffersEqual(unsigned char*, unsigned int,
											unsigned char*, unsigned int);
		static bool isFilenameValid(std::string);
		static bool fileAlreadyExists(std::string);
		static int storeFileContent(std::string, unsigned char*, unsigned int);

};

#endif 
