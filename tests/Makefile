SDE=../sde$(shell python3-config --extension-suffix)

test: run_test_encrypter run_test_passwordencrypter run_test_dataaccess run_test_basic pytest_basic

test_encrypter: test_encrypter.cpp ../sde.o
	g++ -std=c++14 -o test_encrypter ../sde.o test_encrypter.cpp -I ../ -l:libcryptopp.a

run_test_encrypter: test_encrypter
	./test_encrypter

test_passwordencrypter: test_passwordencrypter.cpp ../sde.o
	g++ -std=c++14 -o test_passwordencrypter ../sde.o test_passwordencrypter.cpp -I ../ -l:libcryptopp.a

run_test_passwordencrypter: test_passwordencrypter
	./test_passwordencrypter

test_dataaccess: test_dataaccess.cpp ../sde.o
	g++ -std=c++14 -o test_dataaccess ../sde.o test_dataaccess.cpp -I ../ -l:libcryptopp.a

run_test_dataaccess: test_dataaccess
	./test_dataaccess

test_basic: test_basic.cpp ../sde.o
	g++ -std=c++14 -o test_basic ../sde.o test_basic.cpp -I ../ -l:libcryptopp.a

run_test_basic: test_basic
	./test_basic

pytest_basic: $(SDE)
	python3 test_basic.py
