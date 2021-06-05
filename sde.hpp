#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <sstream>
#include <string>

namespace SDE {

class Encrypter {
   public:
	Encrypter();

	CryptoPP::RSA::PublicKey getPublicKey();
	CryptoPP::RSA::PrivateKey getPrivateKey();
	std::string getEncodedPublicKey();
	std::string getEncodedPrivateKey();
	void setEncodedPublicKey(std::string encodedKey);
	void setEncodedPrivateKey(std::string encodedKey);
	std::string encryptString(std::string plainText);
	std::string decryptString(std::string encrypted);

   private:
	template <typename Key>
	std::string encodeKey(const Key& key);

	template <typename Key>
	const Key decodeKey(std::string& encodedKey);

	CryptoPP::AutoSeededRandomPool* rng = new CryptoPP::AutoSeededRandomPool();
	CryptoPP::RSA::PrivateKey* privateKey = nullptr;
	CryptoPP::RSA::PublicKey* publicKey = nullptr;
};

class PasswordEncrypter {
   public:
	PasswordEncrypter(std::string password);

	std::string encryptString(std::string plainText);
	std::string decryptString(std::string encrypted);

   private:
	CryptoPP::SecByteBlock key;
};

class DataAccess {
   public:
	DataAccess(std::string password);
	DataAccess(std::string _encodedPublicKey, std::string _encryptedPrivateKey, std::string _encryptedDataKey);

	void encryptDataKey();
	void decryptDataKey(std::string password);
	void changePassword(std::string oldPassword, std::string newPassword);
	std::string getPublicKey();
	std::string getEncryptedPrivateKey();
	std::string getEncryptedDataKey();

   private:
	bool locked;
	Encrypter dataKeyEncrypter;
	std::string encryptedPrivateKey;
	std::string dataKey;
	std::string encryptedDataKey;
};

class Data {
   public:
	Data(std::string _data);
	Data(CryptoPP::RSA::PublicKey _publicKey, std::string _encryptedData);

	void encryptData();
	void decryptData(DataAccess access);
	void giveAccessTo(DataAccess access);

   private:
	bool locked;
	Encrypter dataEncrypter;
	std::string data;
	std::string encryptedData;
};

}  // namespace SDE
