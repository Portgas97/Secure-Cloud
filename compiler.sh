g++ server/src/*.cpp common/src/*.cpp -o server.out -O2 -lcrypto -Wall -lstdc++fs -Wextra -Wshadow -Wnon-virtual-dtor -pedantic -Wformat=2

g++ client/src/*.cpp common/src/*.cpp -o client.out -O2 -lcrypto -Wall -lstdc++fs -Wextra -Wshadow -Wnon-virtual-dtor -pedantic -Wformat=2

#  to enable for memory information: 
# -fsanitize=address
