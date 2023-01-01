#ifndef __bip32_h
#define __bip32_h

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

typedef struct bip32_t {
    bool testnet;
} bip32_t;

int bip32_init(bip32_t *ctx, bool testnet);
int bip32_master_key_from_seed(bip32_t *ctx, uint8_t *seed, size_t seed_size,
                               char *result, size_t *size);

#endif
