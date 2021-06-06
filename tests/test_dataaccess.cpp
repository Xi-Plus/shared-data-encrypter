#include <cassert>

#include "sde.hpp"

int main() {
	std::string ALICE_PASS = "password for alice";

	SDE::AESEncrypter passEncrypter = SDE::AESEncrypter(ALICE_PASS);
	SDE::DataAccess alice = SDE::DataAccess(ALICE_PASS);

	try {
		alice.getEncryptedDataKey();
		assert(false);
	} catch (const std::exception& e) {
		std::cerr << e.what() << '\n';
	}
}
