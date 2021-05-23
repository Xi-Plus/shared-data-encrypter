build: sde.o

sde.o: sde.cpp sde.hpp
	g++ -std=c++14 -c -o sde.o sde.cpp
