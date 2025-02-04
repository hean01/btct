#ifndef __bip32_h
#define __bip32_h

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

typedef struct bip32_key_t {
    bool public;
    uint8_t key[32];
    uint8_t chain[32];
    uint8_t parent_fingerprint[4];
    uint8_t depth;
    uint32_t index;
} bip32_key_t;

int bip32_key_init_from_entropy(bip32_key_t *bip32_key_ctx, uint8_t *entropy, size_t size);
int bip32_key_serialize(bip32_key_t *ctx, bool private, bool encoded,
			uint8_t *result, size_t *size);
int bip32_key_to_wif(bip32_key_t *ctx, uint8_t *result, size_t *size);

#endif
