#include <pybind11/numpy.h>
#include <pybind11/operators.h>
#include <pybind11/pybind11.h>

#include "sde.cpp"

PYBIND11_MODULE(sde, m) {
	m.doc() = "shared-data-encrypter";

	// Ref: https://pybind11.readthedocs.io/en/stable/classes.html
	pybind11::class_<SDE::DataAccess>(m, "DataAccess")
		.def(pybind11::init<const std::string &>())
		.def(pybind11::init<const std::string &, const std::string &, const std::string &>())
		.def("encryptDataKey", &SDE::DataAccess::encryptDataKey)
		.def("decryptDataKey", &SDE::DataAccess::decryptDataKey)
		.def("changePassword", &SDE::DataAccess::changePassword)
		.def("getUserPublicKey", &SDE::DataAccess::getUserPublicKey)
		.def("getEncryptedUserPrivateKey", &SDE::DataAccess::getEncryptedUserPrivateKey)
		.def("getEncryptedDataKey", &SDE::DataAccess::getEncryptedDataKey);

	pybind11::class_<SDE::Data>(m, "Data")
		.def("newFromPlain", &SDE::Data::newFromPlain)
		.def("newFromEncrypted", &SDE::Data::newFromEncrypted)
		.def("encryptData", &SDE::Data::encryptData)
		.def("decryptData", &SDE::Data::decryptData)
		.def("giveAccessTo", &SDE::Data::giveAccessTo);
}
