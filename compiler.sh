g++ server/src/*.cpp common/utilities/*.cpp -o server.out -lcrypto -Wall

g++ client/src/*.cpp common/utilities/*.cpp -o client.out -lcrypto -Wall
# to be enabled: 
#-O2: compiler optimizations, -fsanitize, -Wextra, -Wshadow,  -Wnon-virtual-dtor -pedantic -Wformat=2
# removed -lpthread
