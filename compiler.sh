g++ server/src/*.cpp common/utilities/*.cpp -o server.out -lcrypto -Wall -lstdc++fs

g++ client/src/*.cpp common/utilities/*.cpp -o client.out -lcrypto -Wall -lstdc++fs
# to be enabled: 
#-O2: compiler optimizations, -fsanitize, -Wextra, -Wshadow,  -Wnon-virtual-dtor -pedantic -Wformat=2
# removed -lpthread
