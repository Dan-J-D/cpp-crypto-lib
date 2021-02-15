#include "firesaber.h"
#include "firesaber/api.h"

bool GenerateKey(unsigned char* out_public_key, unsigned char* out_secret_key)
{
	return crypto_kem_keypair(out_public_key, out_secret_key) == 0;
}

bool Encapsulate(unsigned char* out_cipher_text, unsigned char* out_shared_secret, unsigned char* public_key)
{
	return crypto_kem_enc(out_cipher_text, out_shared_secret, public_key) == 0;
}

bool Decapsulate(unsigned char* out_shared_secret, unsigned char* cipher_text, unsigned char* secret_key)
{
	return crypto_kem_dec(out_shared_secret, cipher_text, secret_key) == 0;
}

kem_t* firesaber_kem()
{
	kem_t* k = new_kem();
	k->name = (char*)"FireSaber";
	k->secret_key_len = SABER_SECRETKEYBYTES;
	k->public_key_len = SABER_PUBLICKEYBYTES;
	k->shared_secret_len = SABER_KEYBYTES;
	k->cipher_text_len = SABER_BYTES_CCA_DEC;
	k->GenerateKey = GenerateKey;
	k->Encapsulate = Encapsulate;
	k->Decapsulate = Decapsulate;
	return k;
}
