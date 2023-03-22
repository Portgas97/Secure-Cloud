g++ server/src/*.cpp common/utilities/*.cpp -o server.out -O2 -lcrypto -Wall -fsanitize=address -Wextra -Wshadow -Wnon-virtual-dtor -pedantic -Wformat=2 -lstdc++fs

g++ client/src/*.cpp common/utilities/*.cpp -o client.out -O2 -lcrypto -Wall -fsanitize=address -Wextra -Wshadow -Wnon-virtual-dtor -pedantic -Wformat=2 -lstdc++fs

# to be enabled: 
#-O2: compiler optimizations, -fsanitize, -Wextra, -Wshadow,  -Wnon-virtual-dtor -pedantic -Wformat=2
# removed -lpthread
