#include <iostream>
#include "ClientConnectionManager.h"

int main()
{
    ClientConnectionManager client_connection_manager = ClientConnectionManager();
    client_connection_manager.sendHello();
    client_connection_manager.receiveHello();
	client_connection_manager.sendFinalHandshakeMessage();
}
