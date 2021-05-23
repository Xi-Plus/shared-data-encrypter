#include "sde.hpp"

SDE::DataAccess::DataAccess(){

};

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
