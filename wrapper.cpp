#include <pybind11/numpy.h>
#include <pybind11/operators.h>
#include <pybind11/pybind11.h>

#include "sde.cpp"

PYBIND11_MODULE(sde, m) {
	m.doc() = "shared-data-encrypter";

	// Ref: https://pybind11.readthedocs.io/en/stable/classes.html
	pybind11::class_<SDE::DataAccess>(m, "DataAccess")
		.def(pybind11::init<const std::string &>())
		// .def(pybind11::init<const std::string &, const std::string &, const std::string &>())
		;
}
