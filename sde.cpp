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

#include <exception>

/* RSAEncrypter */
SDE::RSAEncrypter::RSAEncrypter() {
	CryptoPP::InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(*rng, 2048);

	privateKey = new CryptoPP::RSA::PrivateKey(params);
	publicKey = new CryptoPP::RSA::PublicKey(params);
};

CryptoPP::RSA::PublicKey SDE::RSAEncrypter::getPublicKey() {
	return *(this->publicKey);
}

std::string SDE::RSAEncrypter::getEncodedPublicKey() {
	return encodeKey<CryptoPP::RSA::PublicKey>(getPublicKey());
}

CryptoPP::RSA::PrivateKey SDE::RSAEncrypter::getPrivateKey() {
	return *(this->privateKey);
}
std::string SDE::RSAEncrypter::getEncodedPrivateKey() {
	return encodeKey<CryptoPP::RSA::PrivateKey>(getPrivateKey());
}

void SDE::RSAEncrypter::setEncodedPublicKey(std::string encodedKey) {
	*(this->publicKey) = decodeKey<CryptoPP::RSA::PublicKey>(encodedKey);
}

void SDE::RSAEncrypter::setEncodedPrivateKey(std::string encodedKey) {
	*(this->privateKey) = decodeKey<CryptoPP::RSA::PrivateKey>(encodedKey);
}

std::string SDE::RSAEncrypter::encryptString(std::string plainText) {
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

std::string SDE::RSAEncrypter::decryptString(std::string encrypted) {
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
		throw e;
	}

	return decrypted;
}

template <typename Key>
std::string SDE::RSAEncrypter::encodeKey(const Key& key) {
	CryptoPP::ByteQueue queue;
	key.Save(queue);

	std::stringstream ss;
	CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(ss));
	queue.TransferTo(encoder);
	encoder.MessageEnd();
	return ss.str();
}

template <typename Key>
const Key SDE::RSAEncrypter::decodeKey(std::string& encodedKey) {
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

/* AESEncrypter */
// https://stackoverflow.com/a/27348134/13509181
SDE::AESEncrypter::AESEncrypter(std::string password) {
	unsigned int iterations = 15000;
	char purpose = 0;

	key = CryptoPP::SecByteBlock(CryptoPP::AES::MAX_KEYLENGTH + CryptoPP::AES::BLOCKSIZE);

	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
	kdf.DeriveKey(key.data(), key.size(), purpose, (byte*)password.data(), password.size(), NULL, 0, iterations);
}

std::string SDE::AESEncrypter::encryptString(std::string plainText) {
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

std::string SDE::AESEncrypter::decryptString(std::string encrypted) {
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

std::string SDE::AESEncrypter::GeneratePassword() {
	CryptoPP::AutoSeededRandomPool prng;
	unsigned char password[32];
	prng.GenerateBlock(password, 32);
	return std::string((const char*)password, 32);
}

/* DataAccess */
SDE::DataAccess::DataAccess(std::string password) {
	SDE::AESEncrypter userPrivateKeyEncrypter = SDE::AESEncrypter(password);

	locked = false;
	userEncrypter = SDE::RSAEncrypter();
	encryptedUserPrivateKey = userPrivateKeyEncrypter.encryptString(userEncrypter.getEncodedPrivateKey());
	dataKey = "";
	encryptedDataKey = "";
}

SDE::DataAccess::DataAccess(std::string _encodedUserPublicKey, std::string _encryptedUserPrivateKey, std::string _encryptedDataKey) {
	locked = true;
	userEncrypter = SDE::RSAEncrypter();
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
	SDE::AESEncrypter userPrivateKeyEncrypter = SDE::AESEncrypter(password);
	userEncrypter.setEncodedPrivateKey(userPrivateKeyEncrypter.decryptString(encryptedUserPrivateKey));

	dataKey = userEncrypter.decryptString(encryptedDataKey);
	locked = false;
}

void SDE::DataAccess::changePassword(std::string oldPassword, std::string newPassword) {
	bool oldLocked = locked;
	decryptDataKey(oldPassword);

	SDE::AESEncrypter userPrivateKeyEncrypter = SDE::AESEncrypter(newPassword);
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

std::string SDE::DataAccess::getDataKey() {
	return dataKey;
}

void SDE::DataAccess::setDataKey(std::string _encodedDataKey) {
	dataKey = _encodedDataKey;
}

/* Data */
SDE::Data SDE::Data::newFromPlain(std::string _data) {
	SDE::Data newData = SDE::Data();
	newData.locked = false;
	newData.dataKey = SDE::AESEncrypter::GeneratePassword();
	newData.dataEncrypter = new SDE::AESEncrypter(newData.dataKey);
	newData.data = _data;
	newData.encryptedData = newData.dataEncrypter->encryptString(newData.data);
	return newData;
};

SDE::Data SDE::Data::newFromEncrypted(std::string _encryptedData) {
	SDE::Data newData = SDE::Data();
	newData.locked = true;
	newData.dataKey = "";
	newData.data = "";
	newData.encryptedData = _encryptedData;
	return newData;
};

void SDE::Data::encryptData() {
	if (!locked) {
		encryptedData = dataEncrypter->encryptString(data);
	}
	data = "";
	locked = true;
}

void SDE::Data::decryptData(DataAccess& access) {
	dataEncrypter = new SDE::AESEncrypter(access.getDataKey());
	data = dataEncrypter->decryptString(encryptedData);
	locked = false;
}

void SDE::Data::giveAccessTo(DataAccess& access) {
	if (locked) {
		throw std::runtime_error("Data is locked");
	}

	access.setDataKey(dataKey);
};

std::string SDE::Data::getData() {
	if (locked) {
		throw std::runtime_error("Data is locked");
	}

	return data;
}

std::string SDE::Data::getEncryptedData() {
	return encryptedData;
}
