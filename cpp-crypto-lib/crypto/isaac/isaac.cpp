#include "isaac.h"

#include <random>

#include "isaac/rand.h"
#include "../chacha20-poly1305/chacha20-poly1305.h"

static randctx* ctx = 0;
void init_isaac()
{
	ctx = (randctx*)malloc(sizeof(randctx));
	ctx->randa = ctx->randb = ctx->randc = (ub4)0;
	randomize_isaac();
}

void uninit_isaac()
{
	delete ctx;
}

std::mt19937 internal_random_seeded()
{
	std::mt19937 rng;
	std::random_device rdev;
	std::seed_seq::result_type data[std::mt19937::state_size];
	std::generate_n(data, std::mt19937::state_size, std::ref(rdev));
	std::seed_seq prng_seed(data, data + std::mt19937::state_size);
	rng.seed(prng_seed);
	return rng;
}

void gen_rand(std::mt19937& rand, unsigned char* data, unsigned int size)
{
	for (unsigned int i = 0; i < size; i++)
		data[i] = (unsigned char)rand();
}

void randomize_isaac()
{
	std::mt19937 gen = internal_random_seeded();
	sync_key_t* chacha = chacha20_poly1305_key();

	unsigned char* data = (unsigned char*)malloc((RANDSIZL * 4 - chacha->cipher_text_extra_size) + (chacha->key_size) + (chacha->nonce_size) + RANDSIZL * 4);

	unsigned char* seed = data;
	unsigned char* key = seed + (RANDSIZL * 4 - chacha->cipher_text_extra_size);
	unsigned char* nonce = key + chacha->key_size;
	unsigned char* enc_seed = nonce + chacha->nonce_size;

	gen_rand(gen, data, enc_seed - data);

	chacha->Encrypt(seed, RANDSIZL * 4 - chacha->cipher_text_extra_size, key, nonce, enc_seed);

	for (unsigned char i = 0; i < RANDSIZL - 1; i++)
		memcpy((void*)(ctx->randrsl + i), (void*)(enc_seed + i * 4), 4);

	free(data);
	delete chacha;

	randinit(ctx, 1);
	isaac(ctx);
	isaac(ctx);
}

int rand_int()
{
	return random(ctx);
}

void rand_bytes(unsigned char* bytes, unsigned int bytes_count)
{
	for (unsigned int i = 0; i < bytes_count; i++)
	{
		*(bytes + i) = ((unsigned char*)&random(ctx))[0];
	}
}
