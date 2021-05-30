#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <iostream>
#include <sstream>
#include <string>

template <typename Key>
std::string EncodeKey(const Key& key) {
	CryptoPP::ByteQueue queue;
	key.Save(queue);

	std::stringstream ss;
	CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(ss));
	queue.TransferTo(encoder);
	encoder.MessageEnd();
	return ss.str();
}

int main() {
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 2048);
	CryptoPP::RSA::PrivateKey privateKey(params);
	CryptoPP::RSA::PublicKey publicKey(params);

	std::cout << "private: " << std::endl;
	std::cout << EncodeKey(privateKey) << std::endl;
	std::cout << "public: " << std::endl;
	std::cout << EncodeKey(publicKey) << std::endl;
	// CryptoPP::ByteQueue queue;
	// publicKey.Save(queue);

	// CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
	// queue.TransferTo(encoder);
	// encoder.MessageEnd();
	// std::cout << std::endl;
}
