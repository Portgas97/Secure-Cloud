#include "UtilityManager.h"

/*
	It returns true if in the directory passed as an argument there is a sub
	directory named as the username passed as an argument, false otherwise
*/
bool UtilityManager::isUserPresent(std::string username, std::string directory)
{
    for (const auto & sub_directory : 
			std::experimental::filesystem::directory_iterator(directory))
		if(username == getFilename(sub_directory.path()))
			return true;

	return false;
}

/*
	It takes as argument the file path and obtain the relative filename
*/
std::string UtilityManager::getFilename(std::string file_path_name)
{
	std::experimental::filesystem::path file_path(file_path_name);
	return file_path.filename();
}

/*
	it returns the buffer containing bytes read from the file whose filename is
	passed as an argument.
	It returns also the buffer size.  
*/
unsigned char* UtilityManager::getCertificateFromFile
										(const char* certificate_filename,
										unsigned int& certificate_buffer_size)
{
	// get certificate
	FILE* certificate_file = fopen(certificate_filename, "r");

	if(certificate_file == nullptr)
	{
		std::cout << "Error in fopen" << std::endl;
		exit(1);
	}

	// get file size
	// move the file pointer to the end of the file
	fseek(certificate_file, 0, SEEK_END);
	// returns the file pointer position
	certificate_buffer_size = ftell(certificate_file);
	// move file pointer to the beginning of the file
	fseek(certificate_file, 0, SEEK_SET);
	
	
	unsigned char* certificate_buffer = getSmallFileContent(certificate_file,
													certificate_buffer_size);

	fclose(certificate_file);
	return certificate_buffer;
}

/*
	It returns file_size bytes read from the file passed as an argument
*/
unsigned char* UtilityManager::getSmallFileContent(FILE* file, 
													unsigned int file_size)
{
	unsigned char* buffer = (unsigned char*) 
											calloc(1, file_size);

	if(buffer == nullptr) 
	{ 
		std::cout << "Error in calloc" << std::endl; 
		exit(1); 
	}

	// actual read
	unsigned int return_value = fread(buffer, 1, file_size, file);

	if(return_value < file_size) 
	{ 
		std::cout << "Error in fread" << std::endl;
		exit(1); 
	}
	return buffer;
}

/*
	It returns a list of filenames of file belonging to the directory whose
	name is passed as argument
*/
std::string UtilityManager::getDirectoryFilenames(std::string directory_name)
{
	std::string directory_filenames;
    for (const auto & file: 
			std::experimental::filesystem::directory_iterator(directory_name))
		directory_filenames += "\t" + getFilename(file.path()) + "\n";

	return directory_filenames;
}


void UtilityManager::printBuffer(unsigned char* buffer, 
								unsigned int buffer_size)
{
    for(unsigned int i = 0; i < buffer_size; i++)
        std::cout << buffer[i];

    std::cout << std::endl;
}

/*
	It compares two byteStreams and returns 1 if they are equal, 0 otherwise
*/
unsigned int UtilityManager::areBuffersEqual(unsigned char* buffer1, 
										unsigned int buffer1_size,
										unsigned char* buffer2,
										unsigned int buffer2_size)
{
	if(buffer1_size != buffer2_size)
		return 0;

    for(unsigned int i = 0; i < buffer1_size; i++)
		if(buffer1[i] != buffer2[i])
			return 0;

	return 1;
}

bool UtilityManager::isFilenameValid(std::string filename) 
{
	if(filename.length() > MAX_FILENAME_SIZE)
		return false;

	const std::regex pattern("^[A-Za-z0-9]+\\.[A-Za-z0-9]+$");
	return regex_match(filename, pattern);
}


bool UtilityManager::fileAlreadyExists(std::string filename)
{
    std::ifstream infile(filename);
    return infile.good();
}


/*
	It stores the file_content in the passed file.
	It returns -1 in case of error, 0 otherwise.
*/
int UtilityManager::storeFileContent(std::string filename, 
												unsigned char* file_content,
												unsigned int file_content_size)
{
	FILE* file = fopen(filename.c_str(), "ab");
	if(file == nullptr) 
		return -1;

	unsigned int written_file_content_size = fwrite(file_content, 
													sizeof(unsigned char),
													file_content_size, 
													file);

	if(written_file_content_size >= UINT32_MAX || 
								written_file_content_size < file_content_size)
		return -1;

	fclose(file);
	CryptographyManager::unoptimizedMemset(file_content, file_content_size);
	return 0;
}

