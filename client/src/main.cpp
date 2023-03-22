#include <iostream>
#include "ClientConnectionManager.h"

int main()
{
    ClientConnectionManager client_connection_manager = 
													ClientConnectionManager();
	client_connection_manager.handleHandshake();
	client_connection_manager.retrieveCommand();

	std::cout << "no more operations to perform, closing..." << std::endl;
	return 0;
}
