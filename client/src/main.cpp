#include <iostream>
#include "ClientConnectionManager.h"

int main()
{
    ClientConnectionManager client_connection_manager = 
													ClientConnectionManager();
	client_connection_manager.handleHandshake();
}
