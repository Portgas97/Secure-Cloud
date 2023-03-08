g++ server/*.cpp common/utilities/*.cpp -o server.out -lcrypto -lpthread -Wall

g++ client/*.cpp common/utilities/*.cpp -o client.out -lcrypto -lpthread -Wall
