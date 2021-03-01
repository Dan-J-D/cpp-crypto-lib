#include "rand.h"
#include "../chacha20-poly1305/chacha20-poly1305/rfc8439.h"

#include <cstdlib>
#include <memory>

typedef struct _rand_state
{
	unsigned char* seed;
	unsigned char* data;
	unsigned char* nonce;
} rand_state;
static rand_state* state;

void init_rand_state()
{
	state = (rand_state*)malloc(sizeof(rand_state));

	state->seed = (unsigned char*)malloc(32);
	memset(state->seed, 0, 32);
	state->data = (unsigned char*)malloc(32);
	memset(state->data, 0, 32);
	state->nonce = (unsigned char*)malloc(16);
	memset(state->nonce, 0, 16);
}

void uninit_rand_state()
{
	free(state->seed);
	free(state->data);
	free(state->nonce);
	free(state);
}

void get_rand_seed(unsigned char seed[32])
{
	memcpy(seed, state->seed, 32);
}

void seed_rand(unsigned char seed[32])
{
	memcpy(state->seed, seed, 32);
	reseed_rand();
}

void reseed_rand()
{
	state->nonce[0] = 2;
	chacha20_xor_stream(state->data, state->data, 32, state->seed, state->nonce, 1);
	memcpy(state->seed, state->data, 32);
	state->nonce[0] = 1;
	chacha20_xor_stream(state->data, state->data, 32, state->seed, state->nonce, 1);
}

void rand_bytes(unsigned char* bytes, unsigned int size)
{
	for (unsigned int i = 0; i < size; i += 32)
	{
		memcpy(bytes + i * 32, state->data, (size - i > 32) ? 32 : size - i);
		reseed_rand();
	}
}
