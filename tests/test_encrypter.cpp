#include <cryptopp/cryptlib.h>

#include <cassert>
#include <string>

#include "sde.hpp"

int main() {
	SDE::Encrypter encrypter = SDE::Encrypter();

	std::cout << "public: " << std::endl;
	std::cout << encrypter.getEncodedPublicKey() << std::endl;

	std::cout << "private: " << std::endl;
	std::cout << encrypter.getEncodedPrivateKey() << std::endl;

	std::string plainText = "secret text";
	std::cout << "plainText: " << plainText << std::endl;

	std::string encrypted = encrypter.encryptString(plainText);
	std::cout << "encrypted: " << encrypted << std::endl;

	SDE::Encrypter encrypter2 = SDE::Encrypter();

	std::string faildecrypted = encrypter2.decryptString(encrypted);
	std::cout << "fail decrypted: " << faildecrypted << std::endl;
	assert(plainText != faildecrypted);

	encrypter2.setEncodedPrivateKey(encrypter.getEncodedPrivateKey());

	std::string decrypted = encrypter2.decryptString(encrypted);
	std::cout << "decrypted: " << decrypted << std::endl;
	assert(plainText == decrypted);
}
