#include <iostream>
#include "../common/utilities/ClientConnectionManager.h"

int main()
{
    ClientConnectionManager client_connection_manager = ClientConnectionManager();
    client_connection_manager.sendHello();
}