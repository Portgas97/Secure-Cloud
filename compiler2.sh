g++ server/src/*.cpp common/utilities/*.cpp -o server.out -lcrypto -Wall -fsanitize=address -Wextra -Wshadow  -Wnon-virtual-dtor -pedantic -Wformat=2

g++ client/src/*.cpp common/utilities/*.cpp -o client.out -lcrypto -Wall -fsanitize=address -Wextra -Wshadow  -Wnon-virtual-dtor -pedantic -Wformat=2

# to be enabled: 
#-O2: compiler optimizations, -fsanitize, -Wextra, -Wshadow,  -Wnon-virtual-dtor -pedantic -Wformat=2
# removed -lpthread