g++ server/main.cpp common/utilities/ConnectionManager.cpp common/utilities/ServerConnectionManager.cpp common/utilities/CryptoManager.cpp -o server -lcrypto -lpthread

g++ client/main.cpp common/utilities/ConnectionManager.cpp common/utilities/ClientConnectionManager.cpp common/utilities/CryptoManager.cpp -o client -lcrypto -lpthread
