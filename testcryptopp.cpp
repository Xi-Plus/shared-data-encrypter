#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <iostream>
#include <sstream>
#include <string>

std::string Encode(CryptoPP::ByteQueue& queue) {
	std::stringstream ss;
	CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(ss));
	queue.TransferTo(encoder);
	encoder.MessageEnd();
	return ss.str();
}

std::string EncodePrivateKey(CryptoPP::RSA::PrivateKey& key) {
	CryptoPP::ByteQueue queue;
	key.DEREncodePrivateKey(queue);

	return Encode(queue);
}

std::string EncodePublicKey(CryptoPP::RSA::PublicKey& key) {
	CryptoPP::ByteQueue queue;
	key.DEREncodePublicKey(queue);

	return Encode(queue);
}

int main() {
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 2048);
	CryptoPP::RSA::PrivateKey privateKey(params);
	CryptoPP::RSA::PublicKey publicKey(params);

	std::cout << "private: " << EncodePrivateKey(privateKey) << std::endl;
	std::cout << "public: " << EncodePublicKey(publicKey) << std::endl;
	// CryptoPP::ByteQueue queue;
	// publicKey.Save(queue);

	// CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
	// queue.TransferTo(encoder);
	// encoder.MessageEnd();
	// std::cout << std::endl;
}
