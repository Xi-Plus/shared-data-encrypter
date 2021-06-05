#include "sde.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/rsa.h>

/* Encrypter */
SDE::Encrypter::Encrypter() {
	CryptoPP::InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(*rng, 2048);

	privateKey = new CryptoPP::RSA::PrivateKey(params);
	publicKey = new CryptoPP::RSA::PublicKey(params);
};

CryptoPP::RSA::PublicKey SDE::Encrypter::getPublicKey() {
	return *(this->publicKey);
}

std::string SDE::Encrypter::getEncodedPublicKey() {
	return encodeKey<CryptoPP::RSA::PublicKey>(getPublicKey());
}

CryptoPP::RSA::PrivateKey SDE::Encrypter::getPrivateKey() {
	return *(this->privateKey);
}
std::string SDE::Encrypter::getEncodedPrivateKey() {
	return encodeKey<CryptoPP::RSA::PrivateKey>(getPrivateKey());
}

void SDE::Encrypter::setEncodedPublicKey(std::string encodedKey) {
	*(this->publicKey) = decodeKey<CryptoPP::RSA::PublicKey>(encodedKey);
}

void SDE::Encrypter::setEncodedPrivateKey(std::string encodedKey) {
	*(this->privateKey) = decodeKey<CryptoPP::RSA::PrivateKey>(encodedKey);
}

std::string SDE::Encrypter::encryptString(std::string plainText) {
	std::string encrypted;

	CryptoPP::RSAES_OAEP_SHA_Encryptor e(*publicKey);
	CryptoPP::StringSource(
		plainText, true,
		new CryptoPP::PK_EncryptorFilter(
			*rng,
			e,
			new CryptoPP::StringSink(encrypted)));

	return encrypted;
}

std::string SDE::Encrypter::decryptString(std::string encrypted) {
	std::string decrypted;

	CryptoPP::RSAES_OAEP_SHA_Decryptor d(*privateKey);

	try {
		CryptoPP::StringSource(
			encrypted, true,
			new CryptoPP::PK_DecryptorFilter(
				*rng, d,
				new CryptoPP::StringSink(decrypted)));

	} catch (const CryptoPP::Exception& e) {
		std::cerr << e.what() << '\n';
		return "";
	}

	return decrypted;
}

template <typename Key>
std::string SDE::Encrypter::encodeKey(const Key& key) {
	CryptoPP::ByteQueue queue;
	key.Save(queue);

	std::stringstream ss;
	CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(ss));
	queue.TransferTo(encoder);
	encoder.MessageEnd();
	return ss.str();
}

template <typename Key>
const Key SDE::Encrypter::decodeKey(std::string& encodedKey) {
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

/* PasswordEncrypter */
// https://stackoverflow.com/a/27348134/13509181
SDE::PasswordEncrypter::PasswordEncrypter(std::string password) {
	unsigned int iterations = 15000;
	char purpose = 0;

	key = CryptoPP::SecByteBlock(CryptoPP::AES::MAX_KEYLENGTH + CryptoPP::AES::BLOCKSIZE);

	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
	kdf.DeriveKey(key.data(), key.size(), purpose, (byte*)password.data(), password.size(), NULL, 0, iterations);
}

std::string SDE::PasswordEncrypter::encryptString(std::string plainText) {
	std::string encrypted;

	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption encryption;
	encryption.SetKeyWithIV(key, CryptoPP::AES::MAX_KEYLENGTH, key + CryptoPP::AES::MAX_KEYLENGTH);

	CryptoPP::StringSource encryptor(
		plainText, true,
		new CryptoPP::StreamTransformationFilter(
			encryption,
			new CryptoPP::StringSink(encrypted)));

	return encrypted;
}

std::string SDE::PasswordEncrypter::decryptString(std::string encrypted) {
	std::string decrypted;

	CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption decryption;
	decryption.SetKeyWithIV(key, CryptoPP::AES::MAX_KEYLENGTH, key + CryptoPP::AES::MAX_KEYLENGTH);

	CryptoPP::StringSource decryptor(
		encrypted, true,
		new CryptoPP::StreamTransformationFilter(
			decryption,
			new CryptoPP::StringSink(decrypted)));

	return decrypted;
}

/* DataAccess */
SDE::DataAccess::DataAccess(std::string password) {
	SDE::PasswordEncrypter userPrivateKeyEncrypter = SDE::PasswordEncrypter(password);

	locked = false;
	userEncrypter = SDE::Encrypter();
	encryptedUserPrivateKey = userPrivateKeyEncrypter.encryptString(userEncrypter.getEncodedPrivateKey());
	dataKey = "";
	encryptedDataKey = "";
}

SDE::DataAccess::DataAccess(std::string _encodedUserPublicKey, std::string _encryptedUserPrivateKey, std::string _encryptedDataKey) {
	locked = true;
	userEncrypter = SDE::Encrypter();
	userEncrypter.setEncodedPublicKey(_encodedUserPublicKey);
	encryptedUserPrivateKey = _encryptedUserPrivateKey;
	dataKey = "";
	encryptedDataKey = _encryptedDataKey;
}

void SDE::DataAccess::encryptDataKey() {
	encryptedDataKey = userEncrypter.encryptString(dataKey);
	dataKey = "";
	locked = true;
}

void SDE::DataAccess::decryptDataKey(std::string password) {
	SDE::PasswordEncrypter userPrivateKeyEncrypter = SDE::PasswordEncrypter(password);
	userEncrypter.setEncodedPrivateKey(userPrivateKeyEncrypter.decryptString(encryptedUserPrivateKey));

	dataKey = userEncrypter.decryptString(encryptedDataKey);
	locked = false;
}

void SDE::DataAccess::changePassword(std::string oldPassword, std::string newPassword) {
	bool oldLocked = locked;
	decryptDataKey(oldPassword);

	SDE::PasswordEncrypter userPrivateKeyEncrypter = SDE::PasswordEncrypter(newPassword);
	encryptedUserPrivateKey = userPrivateKeyEncrypter.encryptString(userEncrypter.getEncodedPrivateKey());

	if (oldLocked) {
		encryptDataKey();
	}
}

std::string SDE::DataAccess::getUserPublicKey() {
	return userEncrypter.getEncodedPublicKey();
}

std::string SDE::DataAccess::getEncryptedUserPrivateKey() {
	return encryptedUserPrivateKey;
}

std::string SDE::DataAccess::getEncryptedDataKey() {
	return encryptedDataKey;
}

/* Data */
SDE::Data::Data(std::string _data) {
	locked = false;
};

SDE::Data::Data(CryptoPP::RSA::PublicKey _publicKey, std::string _encryptedData) {
	locked = true;
	// publicKey = _publicKey;
	encryptedData = _encryptedData;
};

void SDE::Data::giveAccessTo(DataAccess access){

};
