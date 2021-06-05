SDE=sde$(shell python3-config --extension-suffix)

build: cpp python

cpp: sde.o

python: $(SDE)

sde.o: sde.cpp
	g++ -std=c++14 -c -o sde.o sde.cpp

$(SDE): sde.cpp wrapper.cpp
	g++ -O3 -Wall -shared -std=c++14 -fPIC $(shell python3-config --includes) -Iextern/pybind11/includes wrapper.cpp -o $(SDE)  -l:libcrypto++.so
#  -lcryptopp
