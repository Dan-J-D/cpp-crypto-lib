#include "chacha20-poly1305.h"

#include "chacha20-poly1305/rfc8439.h"

bool Encrypt(unsigned char* plain_text, int plain_text_len, unsigned char* key, unsigned char* nonce, unsigned char* out_cipher_text)
{
	return portable_chacha20_poly1305_encrypt(out_cipher_text, key, nonce, 0, 0, plain_text, plain_text_len) != -1;
}

bool Decrypt(unsigned char* cipher_text, int cipher_text_len, unsigned char* key, unsigned char* nonce, unsigned char* out_plain_text)
{
	return portable_chacha20_poly1305_decrypt(out_plain_text, key, nonce, 0, 0, cipher_text, cipher_text_len) != -1;
}

key_t* chacha20_poly1305_key()
{
	key_t* k = new_key();
	k->name = (char*)"chacha20-poly1305";
	k->key_size = RFC_8439_KEY_SIZE;
	k->nonce_size = RFC_8439_NONCE_SIZE;
	k->cipher_text_extra_size = RFC_8439_TAG_SIZE;
	k->Encrypt = Encrypt;
	k->Decrypt = Decrypt;
	return k;
}
