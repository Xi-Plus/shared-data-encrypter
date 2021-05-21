main: test

testcryptopp: testcryptopp.cpp
	g++ -std=c++14 -DNDEBUG -g3 -O2 -Wall -Wextra -o testcryptopp testcryptopp.cpp -l:libcryptopp.a

Evp: Evp-symmetric-encrypt.c
	gcc -o Evp Evp-symmetric-encrypt.c -lcrypto

test: Evp testcryptopp
	./Evp
	./testcryptopp
