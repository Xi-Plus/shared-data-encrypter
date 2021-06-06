#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <sstream>
#include <string>

namespace SDE {

/**
 * Core class to encrypt/decrypt strings by <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">RSA</a>.
 */
class RSAEncrypter {
   public:
	RSAEncrypter();

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

/**
 * Core class to encrypt/decrypt strings by <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES</a>.
 */
class AESEncrypter {
   public:
	AESEncrypter(std::string password);

	std::string encryptString(std::string plainText);
	std::string decryptString(std::string encrypted);

	static std::string GeneratePassword();

   private:
	CryptoPP::SecByteBlock key;
};

class DataAccess {
   public:
	DataAccess(std::string password);
	DataAccess(std::string _encodedUserPublicKey, std::string _encryptedUserPrivateKey, std::string _encryptedDataKey);

	void encryptDataKey();
	void decryptDataKey(std::string password);
	void changePassword(std::string oldPassword, std::string newPassword);
	std::string getUserPublicKey();
	std::string getEncryptedUserPrivateKey();
	std::string getEncryptedDataKey();

   private:
	std::string getDataKey();
	void setDataKey(std::string _encodedDataKey);

	bool locked;
	RSAEncrypter userEncrypter;
	std::string encryptedUserPrivateKey;
	std::string dataKey;
	std::string encryptedDataKey;

	friend class Data;
};

class Data {
   public:
	static Data newFromPlain(std::string _data);
	static Data newFromEncrypted(std::string _encryptedData);

	void encryptData();
	void decryptData(DataAccess& access);
	void giveAccessTo(DataAccess& access);
	std::string getData();
	std::string getEncryptedData();

   private:
	Data() = default;

	bool locked;
	AESEncrypter* dataEncrypter = nullptr;
	std::string dataKey;
	std::string data;
	std::string encryptedData;
};

}  // namespace SDE
