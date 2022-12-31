#ifndef __bip39_h
#define __bip39_h

#include <stdlib.h>
#include <inttypes.h>

#include <nettle/sha2.h>
#include <nettle/pbkdf2.h>

typedef struct bip39_t {
    struct sha256_ctx sha256;
} bip39_t;


int bip39_init(bip39_t *ctx);

int bip39_to_mnemonics(bip39_t *ctx, uint8_t *seed, size_t bits,
                       char ***mnemonics, size_t *count);

int bip39_to_seed(bip39_t *ctx, const uint8_t *menomics, size_t mnemonice_size,
                  int iterations,const uint8_t *passphrase,
                  uint8_t *seed);
#endif
