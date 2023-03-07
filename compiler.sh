g++ server/main.cpp common/utilities/ConnectionManager.cpp common/utilities/ServerConnectionManager.cpp common/utilities/CryptographyManager.cpp -o server.out -lcrypto -lpthread

g++ client/main.cpp common/utilities/ConnectionManager.cpp common/utilities/ClientConnectionManager.cpp common/utilities/CryptographyManager.cpp -o client.out -lcrypto -lpthread
