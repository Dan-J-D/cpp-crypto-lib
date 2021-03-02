#!/bin/sh

mkdir ./bin
g++ -I ./include -march=native -O3 ./test/test.cpp ./src/rand/rand.cpp ./src/sha3/sha3.cpp ./src/chacha20-poly1305/chacha20-poly1305.cpp ./src/chacha20-poly1305/chacha20-poly1305/rfc8439.cpp ./src/firesaber/firesaber.cpp ./src/firesaber/firesaber/poly_mul.cpp ./src/firesaber/firesaber/pack_unpack.cpp ./src/firesaber/firesaber/cbd.cpp ./src/firesaber/firesaber/poly.cpp ./src/firesaber/firesaber/SABER_indcpa.cpp ./src/firesaber/firesaber/verify.cpp ./src/firesaber/firesaber/kem.cpp -o ./bin/build