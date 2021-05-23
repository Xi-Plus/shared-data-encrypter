#include <cryptopp/rsa.h>

#include <string>

namespace SDE {

class DataAccess {
   public:
	DataAccess();

	void encryptDataKey();
	void decryptDataKey(std::string password);
	void changePassword(std::string oldPassword, std::string newPassword);
	std::string getEncryptedDataKey();

   private:
	std::string dataKey;
	std::string encryptedDataKey;
};

class Data {
   public:
	Data(std::string _data);
	Data(CryptoPP::RSA::PublicKey _publicKey, std::string _encryptedData);

	void encrytptData();
	void decryptData(DataAccess access);
	void giveAccessTo(DataAccess access);

   private:
	bool locked;
	CryptoPP::RSA::PublicKey publicKey;
	std::string data;
	std::string encryptedData;
};

}  // namespace SDE
