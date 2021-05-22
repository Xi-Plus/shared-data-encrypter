#include <cryptopp/rsa.h>

#include <string>

namespace SDE {

class User {
   public:
	User();

   private:
};

class Data {
   public:
	Data(std::string _data);
	Data(CryptoPP::RSA::PrivateKey _privateKey, std::string _encryptedData);

   private:
	CryptoPP::RSA::PrivateKey privateKey;
};

}  // namespace SDE
