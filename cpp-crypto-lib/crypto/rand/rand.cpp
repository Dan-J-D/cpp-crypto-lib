#include "rand.h"
#include "../chacha20-poly1305/chacha20-poly1305/rfc8439.h"

#define _CRT_RAND_S
#include <cstdlib>
#include <memory>
#include <memory.h>
#include <chrono>
#include <immintrin.h>

typedef struct _rand_state
{
	unsigned char* seed;
	unsigned char* nonce;
} rand_state;
static rand_state* state;

void init_rand_state()
{
	state = (rand_state*)malloc(sizeof(rand_state));
	
	state->seed = (unsigned char*)malloc(32);
	memset(state->seed, 0, 32);
	state->nonce = (unsigned char*)malloc(16);
	memset(state->nonce, 0, 16);
	state->nonce[0] = 1;

	collect_entropy(state->seed);
}

void uninit_rand_state()
{
	free(state->seed);
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
}

void rand_bytes(unsigned char* bytes, unsigned int size)
{
	if (size < 32)
	{
		unsigned char* b = (unsigned char*)alloca(32);
		chacha20_xor_stream(b, b, 32, state->seed, state->nonce, 1);
		memcpy(bytes, b, size);
	}
	else
	{
		chacha20_xor_stream(bytes, bytes, size, state->seed, state->nonce, 1);
	}
	collect_entropy(state->seed);
}

#if defined(__linux__) || defined(__unix__)
#include <fstream>
#include <x86intrin.h>
#include <time.h>
#elif defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__) || defined(_WIN64)
#include <intrin.h>
#include <Windows.h>
#endif

void collect_entropy(unsigned char bytes[32])
{
	/*
	* If you XOR multiple entropies together,
	* the resulting security would be at least
	* the entropy with the most security
	*/

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

#if defined(__linux__)
	// /dev/urandom rand
	std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
	if (urandom && urandom.is_open() && urandom.good())
	{
		unsigned char* r = (unsigned char*)alloca(32);
		urandom.read((char*)r, 32);
		for(unsigned int i = 0; i < 32; i++)
			bytes[i] ^= r[i];
		urandom.close();
	}

	// uptime rand
	std::fstream uptime("/proc/uptime", std::ios::in);
	if (uptime && uptime.good() && uptime.is_open())
	{
		double d = 0;
		uptime >> d;
		d *= 1000;
		uptime.close();

		for (unsigned int i = 0; i < 32; i++)
			bytes[i] ^= ((unsigned char*)&d)[i % sizeof(d)];
	}
#endif

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__) || defined(_WIN64)
	// rand_s rand
	unsigned int i32 = 0;
	for (unsigned int i = 0; i < 32; i++)
	{
		if (i % sizeof(i32) == 0)
			if (rand_s(&i32) != 0) break;
		bytes[i] ^= ((unsigned char*)&i32)[i % sizeof(i32)];
	}

	// uptime rand
	i64 = GetTickCount64();
	for (unsigned int i = 0; i < 32; i++)
		bytes[i] ^= ((unsigned char*)&i64)[i % sizeof(i64)];
#endif
}
