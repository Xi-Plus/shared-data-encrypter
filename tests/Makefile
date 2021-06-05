test: run_test_encrypter run_test_passwordencrypter run_test_basic

test_encrypter: test_encrypter.cpp
	g++ -std=c++14 -o test_encrypter ../sde.o test_encrypter.cpp -I ../ -l:libcryptopp.a

run_test_encrypter: test_encrypter
	./test_encrypter

test_passwordencrypter: test_passwordencrypter.cpp
	g++ -std=c++14 -o test_passwordencrypter ../sde.o test_passwordencrypter.cpp -I ../ -l:libcryptopp.a

run_test_passwordencrypter: test_passwordencrypter
	./test_passwordencrypter

test_basic: test_basic.cpp
	g++ -std=c++14 -o test_basic ../sde.o test_basic.cpp -I ../ -l:libcryptopp.a

run_test_basic: test_basic
	./test_basic
