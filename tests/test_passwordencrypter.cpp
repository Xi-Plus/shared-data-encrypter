#include <cryptopp/cryptlib.h>

#include <cassert>
#include <string>

#include "sde.hpp"

int main() {
	std::string password = "my password";

	SDE::AESEncrypter encrypter = SDE::AESEncrypter(password);

	std::string plainText = "secret text";
	std::cout << "plainText: " << plainText << std::endl;

	std::string encrypted = encrypter.encryptString(plainText);
	std::cout << "encrypted: " << encrypted << std::endl;

	SDE::AESEncrypter encrypter2 = SDE::AESEncrypter(password);

	std::string decrypted = encrypter2.decryptString(encrypted);
	std::cout << "decrypted: " << decrypted << std::endl;
	assert(plainText == decrypted);

	std::cout << "generated password: " << std::endl;
	std::cout << SDE::AESEncrypter::GeneratePassword() << std::endl;
}
