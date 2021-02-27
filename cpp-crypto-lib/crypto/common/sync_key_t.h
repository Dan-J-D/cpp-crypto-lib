#pragma once

#include <string>
#include <stdlib.h>

/* Synchronous Key */
struct sync_key_t
{
	char* name = 0;

	int key_size = 0;
	int nonce_size = 0;
	int cipher_text_extra_size = 0;

	bool(*Encrypt)(unsigned char* plain_text, int plain_text_len, unsigned char* key, unsigned char* nonce, unsigned char* out_cipher_text) = 0;
	bool(*Decrypt)(unsigned char* cipher_text, int cipher_text_len, unsigned char* key, unsigned char* nonce, unsigned char* out_plain_text) = 0;
};

static sync_key_t* new_sync_key()
{
	return (sync_key_t*)malloc(sizeof(sync_key_t));
}
