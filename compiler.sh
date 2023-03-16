g++ server/src/*.cpp common/utilities/*.cpp -o server.out -lcrypto -lpthread -Wall

g++ client/src/*.cpp common/utilities/*.cpp -o client.out -lcrypto -lpthread -Wall

# to be enabled: 
#-O2: compiler optimizations, -fsanitize, -Wextra, -Wshadow,  -Wnon-virtual-dtor -pedantic -Wformat=2