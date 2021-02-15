#pragma once

void init_isaac();

void uninit_isaac();

void randomize_isaac();

int rand_int();

void rand_bytes(unsigned char* bytes, unsigned int bytes_count);
