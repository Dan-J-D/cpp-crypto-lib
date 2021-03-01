#pragma once

void init_rand_state();
void uninit_rand_state();
void get_rand_seed(unsigned char seed[32]);
void seed_rand(unsigned char seed[32]);
void reseed_rand();
void rand_bytes(unsigned char* bytes, unsigned int size);
