#include <cassert>

#include "sde.hpp"

int main() {
	std::string ALICE_PASS = "password for alice";

	SDE::AESEncrypter passEncrypter = SDE::AESEncrypter(ALICE_PASS);
	SDE::DataAccess alice = SDE::DataAccess(ALICE_PASS);

	assert(alice.getEncryptedDataKey() == "");	// EncryptedDataKey must be empty at first
}
