#include <pybind11/numpy.h>
#include <pybind11/operators.h>
#include <pybind11/pybind11.h>

#include "sde.cpp"

PYBIND11_MODULE(sde, m) {
	m.doc() = "shared-data-encrypter";

	// Ref: https://pybind11.readthedocs.io/en/stable/classes.html
	pybind11::class_<SDE::RSAEncrypter>(m, "RSAEncrypter")
		.def(pybind11::init<>())
		.def("getEncodedPublicKey", [](SDE::RSAEncrypter &rsa) {
			return pybind11::bytes(rsa.getEncodedPublicKey());
		})
		.def("getEncodedPrivateKey", [](SDE::RSAEncrypter &rsa) {
			return pybind11::bytes(rsa.getEncodedPrivateKey());
		})
		.def("setEncodedPublicKey", &SDE::RSAEncrypter::setEncodedPublicKey)
		.def("setEncodedPrivateKey", &SDE::RSAEncrypter::setEncodedPrivateKey)
		.def("encryptString", [](SDE::RSAEncrypter &rsa, const std::string &text) {
			return pybind11::bytes(rsa.encryptString(text));
		})
		.def("decryptString", [](SDE::RSAEncrypter &rsa, const std::string &text) {
			return pybind11::bytes(rsa.decryptString(text));
		});

	pybind11::class_<SDE::AESEncrypter>(m, "AESEncrypter")
		.def(pybind11::init<const std::string &>())
		.def("encryptString", [](SDE::AESEncrypter &aes, const std::string &text) {
			return pybind11::bytes(aes.encryptString(text));
		})
		.def("decryptString", [](SDE::AESEncrypter &aes, const std::string &text) {
			return pybind11::bytes(aes.decryptString(text));
		})
		.def_static("GeneratePassword", []() {
			return pybind11::bytes(SDE::AESEncrypter::GeneratePassword());
		});

	pybind11::class_<SDE::DataAccess>(m, "DataAccess")
		.def(pybind11::init<const std::string &>())
		.def(pybind11::init<const std::string &, const std::string &, const std::string &>())
		.def("encryptDataKey", &SDE::DataAccess::encryptDataKey)
		.def("decryptDataKey", &SDE::DataAccess::decryptDataKey)
		.def("changePassword", &SDE::DataAccess::changePassword)
		.def("getUserPublicKey", [](SDE::DataAccess &da) {
			return pybind11::bytes(da.getUserPublicKey());
		})
		.def("getEncryptedUserPrivateKey", [](SDE::DataAccess &da) {
			return pybind11::bytes(da.getEncryptedUserPrivateKey());
		})
		.def("getEncryptedDataKey", [](SDE::DataAccess &da) {
			return pybind11::bytes(da.getEncryptedDataKey());
		});

	pybind11::class_<SDE::Data>(m, "Data")
		.def_static("newFromPlain", &SDE::Data::newFromPlain)
		.def_static("newFromEncrypted", &SDE::Data::newFromEncrypted)
		.def("encryptData", &SDE::Data::encryptData)
		.def("decryptData", &SDE::Data::decryptData)
		.def("giveAccessTo", &SDE::Data::giveAccessTo)
		.def("getData", [](SDE::Data &data) {
			return pybind11::bytes(data.getData());
		})
		.def("getEncryptedData", [](SDE::Data &data) {
			return pybind11::bytes(data.getEncryptedData());
		});
}
