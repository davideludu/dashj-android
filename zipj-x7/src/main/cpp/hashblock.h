#ifndef HASHBLOCK_H
#define HASHBLOCK_H

#include "sph_blake.h"
#include "sph_bmw.h"
#include "sph_groestl.h"
#include "sph_skein.h"
#include "sph_keccak.h"
#include "sph_luffa.h"
#include "sph_echo.h"
#include <cstdint> // For uint64_t
#include <cstring> // For memcpy

// Define hash sizes
#define HASH512_SIZE 64
#define HASH256_SIZE 32

// Function to trim the hash result to 256 bits
void trim256(const unsigned char *pn, unsigned char *ret)
{
    for (unsigned int i = 0; i < HASH256_SIZE; i++) {
        ret[i] = pn[i];
    }
}

// Function to perform the X7 hashing algorithm
inline bool HashX7(const unsigned char *pbegin, const unsigned char *pend, uint64_t timestamp, unsigned char *pResult)
{
    sph_blake512_context ctx_blake;
    sph_bmw512_context ctx_bmw;
    sph_groestl512_context ctx_groestl;
    sph_skein512_context ctx_skein;
    sph_keccak512_context ctx_keccak;
    sph_luffa512_context ctx_luffa;
    sph_echo512_context ctx_echo;
    static unsigned char pblank[1] = {0};

    unsigned char hash[7][HASH512_SIZE];
    unsigned char temp1[HASH512_SIZE];
    unsigned char temp2[HASH512_SIZE];

    // Incorporate the timestamp into the initial data
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, &timestamp, sizeof(timestamp));
    sph_blake512(&ctx_blake, (pbegin == pend ? pblank : pbegin), (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&ctx_blake, &hash[0]);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, &hash[0], HASH512_SIZE);
    sph_bmw512_close(&ctx_bmw, &hash[1]);

    // XOR operation between Blake512 and BMW512
    std::memcpy(temp1, &hash[0], HASH512_SIZE);
    std::memcpy(temp2, &hash[1], HASH512_SIZE);
    for (int i = 0; i < HASH512_SIZE; ++i) {
        temp2[i] ^= temp1[i];
    }
    std::memcpy(&hash[1], temp2, HASH512_SIZE);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, &hash[1], HASH512_SIZE);
    sph_groestl512_close(&ctx_groestl, &hash[2]);

    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, &hash[2], HASH512_SIZE);
    sph_skein512_close(&ctx_skein, &hash[3]);

    // Another XOR operation
    std::memcpy(temp1, &hash[2], HASH512_SIZE);
    std::memcpy(temp2, &hash[3], HASH512_SIZE);
    for (int i = 0; i < HASH512_SIZE; ++i) {
        temp2[i] ^= temp1[i];
    }
    std::memcpy(&hash[3], temp2, HASH512_SIZE);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, &hash[3], HASH512_SIZE);
    sph_keccak512_close(&ctx_keccak, &hash[4]);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, &hash[4], HASH512_SIZE);
    sph_luffa512_close(&ctx_luffa, &hash[5]);

    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, &hash[5], HASH512_SIZE);
    sph_echo512_close(&ctx_echo, &hash[6]);

    // Final XOR operation
    std::memcpy(temp1, &hash[5], HASH512_SIZE);
    std::memcpy(temp2, &hash[6], HASH512_SIZE);
    for (int i = 0; i < HASH512_SIZE; ++i) {
        temp2[i] ^= temp1[i];
    }
    std::memcpy(&hash[6], temp2, HASH512_SIZE);

    trim256(hash[6], pResult);
    return true;
}

#endif // HASHBLOCK_H
