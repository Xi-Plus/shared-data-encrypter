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
	/**
	 * Create a new RSAEncrypter object.
	 */
	RSAEncrypter();

	/**
	 * Get raw public key for this encrypter.
	 */
	CryptoPP::RSA::PublicKey getPublicKey();

	/**
	 * Get raw private key for this encrypter.
	 */
	CryptoPP::RSA::PrivateKey getPrivateKey();

	/**
	 * Get base64-encoded public key for this encrypter.
	 */
	std::string getEncodedPublicKey();

	/**
	 * Get base64-encoded private key for this encrypter.
	 */
	std::string getEncodedPrivateKey();

	/**
	 * Set base64-encoded public key for this encrypter.
	 *
	 * @param encodedKey Base64-encoded public key
	 */
	void setEncodedPublicKey(std::string encodedKey);

	/**
	 * Set base64-encoded private key for this encrypter.
	 *
	 * @param encodedKey Base64-encoded private key
	 */
	void setEncodedPrivateKey(std::string encodedKey);

	/**
	 * Encrypt a string.
	 *
	 * @param plainText Plain text to be encrypted.
	 */
	std::string encryptString(std::string plainText);

	/**
	 * Decrypt a string.
	 *
	 * @param encrypted Encrypted text to be decrypted.
	 * @exception CryptoPP::Exception The decryption is failed.
	 */
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
	/**
	 * Create a new AESEncrypter object.
	 */
	AESEncrypter(std::string password);

	/**
	 * Encrypt a string.
	 *
	 * @param plainText Plain text to be encrypted.
	 */
	std::string encryptString(std::string plainText);

	/**
	 * Decrypt a string. No exceptions raised when it failed.
	 *
	 * @param encrypted Encrypted text to be decrypted.
	 */
	std::string decryptString(std::string encrypted);

	/**
	 * Generate a key (password) to be used in AESEncrypter.
	 */
	static std::string GeneratePassword();

   private:
	CryptoPP::SecByteBlock key;
};

/**
 * Store access information to Data.
 */
class DataAccess {
   public:
	/**
	 * Create a new DataAccess object.
	 *
	 * @param password Used for AESEncrypter.
	 */
	DataAccess(std::string password);

	/**
	 * Restore DataAccess object from old data.
	 *
	 * @param _encodedUserPublicKey Base64-encoded DataAccess public key.
	 * @param _encryptedUserPrivateKey Encrypted DataAccess private key.
	 * @param _encryptedDataKeyEncrypted Encrypted Data key.
	 */
	DataAccess(std::string _encodedUserPublicKey, std::string _encryptedUserPrivateKey, std::string _encryptedDataKey);

	/**
	 * Encrypt the Data key. It generate encryptedDataKey and destroy dataKey, then lock the access.
	 */
	void encryptDataKey();

	/**
	 * Decrypt the Data key. It restores dataKey from encryptedDataKey, then unlock the access.
	 *
	 * @param password Used for AESEncrypter to decrypt.
	 */
	void decryptDataKey(std::string password);

	/**
	 * Decrypt the dataKey then encrypt it with new password.
	 *
	 * @param oldPassword Old password for AESEncrypter to decrypt.
	 * @param newPassword New password for AESEncrypter to encrypt.
	 */
	void changePassword(std::string oldPassword, std::string newPassword);

	/**
	 * Get DataAccess public key.
	 */
	std::string getUserPublicKey();

	/**
	 * Get encrypted DataAccess private key.
	 */
	std::string getEncryptedUserPrivateKey();

	/**
	 * Get encrypted Data key.
	 */
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

/**
 * Store secret string and their keys.
 */
class Data {
   public:
	/**
	 * Create a new Data with plain text.
	 *
	 * @param _data Plain text to encrypt.
	 */
	static Data newFromPlain(std::string _data);

	/**
	 * Restore old Data with encrypted text.
	 *
	 * @param _encryptedData Encrypted text to decrypt.
	 */
	static Data newFromEncrypted(std::string _encryptedData);

	/**
	 * Encrypt the string. It generate encryptedData and destroy plain data, then lock the data.
	 */
	void encryptData();

	/**
	 * Decrypt the string. It restores plain data from encryptedData, then unlock the data.
	 *
	 * @param access Used for RSAEncrypter to decrypt.
	 */
	void decryptData(DataAccess& access);

	/**
	 * Assign acess permission to DataAcess.
	 *
	 * @param access Who needs the permission.
	 * @exception std::runtime_error The data is locked.
	 */
	void giveAccessTo(DataAccess& access);

	/**
	 * Get plain text.
	 *
	 * @exception std::runtime_error The data is locked.
	 */
	std::string getData();

	/**
	 * Get encrypted string.
	 */
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
