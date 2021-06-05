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

template <typename Key>
const Key decodeKey(std::string& encodedKey) {
	CryptoPP::HexDecoder decoder;
	decoder.Put((byte*)encodedKey.data(), encodedKey.size());
	decoder.MessageEnd();

	CryptoPP::ByteQueue queue;
	decoder.TransferTo(queue);
	queue.MessageEnd();

	Key key;
	key.Load(queue);
	return key;
}

int main() {
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 2048);
	CryptoPP::RSA::PrivateKey privateKey(params);
	CryptoPP::RSA::PublicKey publicKey(params);

	std::string privateStr = EncodeKey(privateKey);
	std::cout << "private: " << std::endl;
	std::cout << privateStr << std::endl;

	std::string publicStr = EncodeKey(publicKey);
	std::cout << "public: " << std::endl;
	std::cout << publicStr << std::endl;

	std::string plainText = "secret text";
	std::cout << "plainText: " << plainText << std::endl;

	std::string encrypted;

	CryptoPP::RSAES_OAEP_SHA_Encryptor e(publicKey);
	CryptoPP::StringSource(
		plainText, true,
		new CryptoPP::PK_EncryptorFilter(
			rng,
			e,
			new CryptoPP::StringSink(encrypted)));

	std::cout << "encrypted: " << encrypted << std::endl;

	auto privateKey2 = decodeKey<CryptoPP::RSA::PrivateKey>(privateStr);

	std::string decrypted;

	CryptoPP::AutoSeededRandomPool rng2;

	CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey2);
	CryptoPP::StringSource(
		encrypted, true,
		new CryptoPP::PK_DecryptorFilter(
			rng2, d,
			new CryptoPP::StringSink(decrypted)));

	std::cout << "decrypted: " << decrypted << std::endl;
}
