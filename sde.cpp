#include "sde.hpp"

#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

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

	} catch (const CryptoPP::InvalidCiphertext& e) {
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

SDE::DataAccess::DataAccess(std::string password) {}
SDE::DataAccess::DataAccess(CryptoPP::RSA::PublicKey _publicKey, std::string _encryptedPrivateKey, std::string _encryptedDataKey) {}

void SDE::DataAccess::encryptDataKey() {
}

void SDE::DataAccess::decryptDataKey(std::string password) {
}

void SDE::DataAccess::changePassword(std::string oldPassword, std::string newPassword) {
}

std::string SDE::DataAccess::getEncryptedDataKey() {
	return encryptedDataKey;
}

SDE::Data::Data(std::string _data) {
	locked = false;
};

SDE::Data::Data(CryptoPP::RSA::PublicKey _publicKey, std::string _encryptedData) {
	locked = true;
	publicKey = _publicKey;
	encryptedData = _encryptedData;
};

void SDE::Data::giveAccessTo(DataAccess access){

};
