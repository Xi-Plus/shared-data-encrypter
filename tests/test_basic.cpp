#include "sde.hpp"

int main() {
	std::string apple_str = "secret for apple";
	std::string banana_str = "secret for apple";

	std::string alice_pass = "password for alice";
	std::string bob_pass = "password for bob";

	// Create data apple
	SDE::Data apple = SDE::Data::newFromPlain(apple_str);

	// Give access to alice for apple
	SDE::DataAccess alice_apple = SDE::DataAccess(alice_pass);
	apple.giveAccessTo(alice_apple);

	apple.encryptData();
	alice_apple.encryptDataKey();

	// Create data banana
	SDE::Data banana = SDE::Data::newFromPlain(banana_str);

	// Give access to alice for banana
	SDE::DataAccess alice_banana = SDE::DataAccess(alice_pass);
	banana.giveAccessTo(alice_banana);

	// Give access to bob for banana
	SDE::DataAccess bob_banana = SDE::DataAccess(bob_pass);
	banana.giveAccessTo(bob_banana);

	banana.encryptData();
	alice_banana.encryptDataKey();
	bob_banana.encryptDataKey();
}
