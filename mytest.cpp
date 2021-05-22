// https://riptutorial.com/openssl/example/16737/generate-rsa-key
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

using namespace std;

int main() {
	EVP_PKEY *pkey;
	pkey = EVP_PKEY_new();

	BIGNUM *bn;
	bn = BN_new();
	BN_set_word(bn, RSA_F4);

	RSA *rsa;
	rsa = RSA_new();
	RSA_generate_key_ex(rsa, 2048, bn, NULL);

	BIO *bp_public = NULL, *bp_private = NULL;
	bp_public = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(bp_public, rsa);

	bp_private = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);

	size_t pri_len;
	size_t pub_len;
	pri_len = BIO_pending(bp_private);
	pub_len = BIO_pending(bp_public);

	char *pri_key;
	char *pub_key;
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pub_len + 1);

	BIO_read(bp_private, pri_key, pri_len);
	BIO_read(bp_public, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	EVP_PKEY_assign_RSA(pkey, rsa);
}
