#pragma once

#include <stdlib.h>

struct kem_t
{
	char* name = 0;

	int secret_key_len = 0;
	int public_key_len = 0;
	int shared_secret_len = 0;
	int cipher_text_len = 0;

	bool(*GenerateKey)(unsigned char* out_public_key, unsigned char* out_secret_key) = 0;
	bool(*Encapsulate)(unsigned char* out_cipher_text, unsigned char* out_shared_secret, unsigned char* public_key) = 0;
	bool(*Decapsulate)(unsigned char* out_shared_secret, unsigned char* cipher_text, unsigned char* secret_key) = 0;
};
