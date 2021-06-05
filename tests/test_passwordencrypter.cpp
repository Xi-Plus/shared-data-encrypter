#include <cryptopp/cryptlib.h>

#include <cassert>
#include <string>

#include "sde.hpp"

int main() {
	std::string password = "my password";

	SDE::PasswordEncrypter encrypter = SDE::PasswordEncrypter(password);

	std::string plainText = "secret text";
	std::cout << "plainText: " << plainText << std::endl;

	std::string encrypted = encrypter.encryptString(plainText);
	std::cout << "encrypted: " << encrypted << std::endl;

	SDE::PasswordEncrypter encrypter2 = SDE::PasswordEncrypter(password);

	std::string decrypted = encrypter2.decryptString(encrypted);
	std::cout << "decrypted: " << decrypted << std::endl;
	assert(plainText == decrypted);

	std::cout << "generated password: " << std::endl;
	std::cout << SDE::PasswordEncrypter::GeneratePassword() << std::endl;
}
