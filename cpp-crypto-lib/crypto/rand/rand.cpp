#include "rand.h"
#include "../chacha20-poly1305/chacha20-poly1305/rfc8439.h"

#define _CRT_RAND_S
#include <cstdlib>
#include <memory>
#include <chrono>
#include <immintrin.h>
#include <intrin.h>

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

	collect_entropy(state->seed);
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
	memcpy(state->data, state->seed, 32);
	memcpy(state->seed, seed, 32);
	reseed_rand();
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
	memcpy(state->data, state->seed, 32);
	collect_entropy(state->seed);
	reseed_rand();
}

#ifdef __linux__
#include <fstream>
#endif

void collect_entropy(unsigned char bytes[32])
{
	// time rand
	unsigned long long i64 = (unsigned long long)std::chrono::high_resolution_clock::now().time_since_epoch().count();
	for (unsigned int i = 0; i < 32; i++)
		bytes[i] ^= ((unsigned char*)&i64)[i % sizeof(i64)];

	// rdtcs rand
	i64 = __rdtsc();
	for (unsigned int i = 0; i < 32; i++)
		bytes[i] ^= ((unsigned char*)&i64)[i % sizeof(i64)];

	// CPU RDSEED rand
	for (unsigned int i = 0; i < 32; i++)
	{
		if (i % sizeof(i64) == 0)
			if (!_rdseed64_step(&i64)) break;
		bytes[i] ^= ((unsigned char*)&i64)[i % sizeof(i64)];
	}

	// /dev/urandom rand
#ifdef __linux__
	std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
	if (urandom && urandom.is_open() && urandom.good())
	{
		unsigned char* r = (unsigned char*)alloca(32);
		urandom.read((char*)r, 32);
		for(unsigned int i = 0; i < 32; i++)
			bytes[i] ^= r[i];
		urandom.close();
	}
#endif

	// rand_s rand
#ifdef _WIN32
	unsigned int i32 = 0;
	for (unsigned int i = 0; i < 32; i++)
	{
		if (i % sizeof(i32) == 0)
			if (rand_s(&i32) != 0) break;
		bytes[i] ^= ((unsigned char*)&i32)[i % sizeof(i32)];
	}
#endif
}
