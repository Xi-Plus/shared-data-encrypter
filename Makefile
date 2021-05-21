main: test

Evp: Evp-symmetric-encrypt.c
	gcc Evp-symmetric-encrypt.c -o Evp -lcrypto

test: Evp
	./Evp
