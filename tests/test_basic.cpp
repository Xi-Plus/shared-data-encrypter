#include "sde.hpp"

int main() {
	SDE::Data apple = SDE::Data("secret for apple");
	SDE::Data banana = SDE::Data("secret for banana");
	SDE::DataAccess alice_apple = SDE::DataAccess();
	SDE::DataAccess alice_banana = SDE::DataAccess();
	SDE::DataAccess bob_banana = SDE::DataAccess();

	apple.giveAccessTo(alice_apple);
	banana.giveAccessTo(alice_banana);
	banana.giveAccessTo(bob_banana);
}
