#include "chacha20-poly1305/chacha20-poly1305.h"

#include "chacha20-poly1305/rfc8439.h"

bool chacha20_poly1305_encrypt(unsigned char* plain_text, int plain_text_len, unsigned char* key, unsigned char* nonce, unsigned char* out_cipher_text)
{
	return portable_chacha20_poly1305_encrypt(out_cipher_text, key, nonce, 0, 0, plain_text, plain_text_len) != -1;
}

bool chacha20_poly1305_decrypt(unsigned char* cipher_text, int cipher_text_len, unsigned char* key, unsigned char* nonce, unsigned char* out_plain_text)
{
	return portable_chacha20_poly1305_decrypt(out_plain_text, key, nonce, 0, 0, cipher_text, cipher_text_len) != -1;
}

bool chacha20_encrypt(unsigned char* plain_text, int plain_text_len, unsigned char* key, unsigned char* nonce, unsigned char* out_cipher_text)
{
	chacha20_xor_stream(out_cipher_text, plain_text, plain_text_len, key, nonce, 1);
	return true;
}

bool chacha20_decrypt(unsigned char* cipher_text, int cipher_text_len, unsigned char* key, unsigned char* nonce, unsigned char* out_plain_text)
{
	chacha20_xor_stream(out_plain_text, cipher_text, cipher_text_len, key, nonce, 1);
	return true;
}

sync_key_t* chacha20_poly1305_key()
{
	sync_key_t* k = new sync_key_t();
	k->name = (char*)"chacha20-poly1305";
	k->key_size = RFC_8439_KEY_SIZE;
	k->nonce_size = RFC_8439_NONCE_SIZE;
	k->cipher_text_extra_size = RFC_8439_TAG_SIZE;
	k->Encrypt = chacha20_poly1305_encrypt;
	k->Decrypt = chacha20_poly1305_decrypt;
	return k;
}

sync_key_t* chacha20_key()
{
	sync_key_t* k = new sync_key_t();
	k->name = (char*)"chacha20";
	k->key_size = CHACHA20_KEY_SIZE;
	k->nonce_size = CHACHA20_NONCE_SIZE;
	k->cipher_text_extra_size = 0;
	k->Encrypt = chacha20_encrypt;
	k->Decrypt = chacha20_decrypt;
	return k;
}
