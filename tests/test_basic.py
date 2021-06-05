import sys
sys.path.append('..')
import sde

apple_str = "secret for apple"
banana_str = "secret for banana"

alice_pass = "password for alice"
bob_pass = "password for bob"

apple = sde.Data.newFromPlain(apple_str)

alice_apple = sde.DataAccess(alice_pass)
apple.giveAccessTo(alice_apple)

apple.encryptData()
alice_apple.encryptDataKey()

banana = sde.Data.newFromPlain(banana_str)

alice_banana = sde.DataAccess(alice_pass)
banana.giveAccessTo(alice_banana)

bob_banana = sde.DataAccess(bob_pass)
banana.giveAccessTo(bob_banana)

apple.encryptData()
alice_apple.encryptDataKey()
bob_banana.encryptDataKey()
