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
	std::string EncodeKey(const Key& key) {
		CryptoPP::ByteQueue queue;
		key.Save(queue);

		std::stringstream ss;
		CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(ss));
		queue.TransferTo(encoder);
		encoder.MessageEnd();
		return ss.str();
	}

	template <typename Key>
	const Key decodeKey(std::string& encodedKey) {
		CryptoPP::HexDecoder decoder;
		decoder.Put((byte*)encodedKey.data(), encodedKey.size());
		decoder.MessageEnd();

		CryptoPP::ByteQueue queue;
		decoder.TransferTo(queue);
		queue.MessageEnd();

		Key key;
		key.Load(queue);
		return key;
	}

	CryptoPP::AutoSeededRandomPool* rng = new CryptoPP::AutoSeededRandomPool();
	CryptoPP::RSA::PrivateKey* privateKey = nullptr;
	CryptoPP::RSA::PublicKey* publicKey = nullptr;
};

class DataAccess {
   public:
	DataAccess(std::string password);
	DataAccess(CryptoPP::RSA::PublicKey _publicKey, std::string _encryptedPrivateKey, std::string _encryptedDataKey);

	void encryptDataKey();
	void decryptDataKey(std::string password);
	void changePassword(std::string oldPassword, std::string newPassword);
	std::string getPublicKey();
	std::string getEncryptedPrivateKey();
	std::string getEncryptedDataKey();

   private:
	CryptoPP::RSA::PublicKey publicKey;
	CryptoPP::RSA::PrivateKey privateKey;
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
	CryptoPP::RSA::PublicKey publicKey;
	std::string data;
	std::string encryptedData;
};

}  // namespace SDE
