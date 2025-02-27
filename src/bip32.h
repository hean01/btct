#ifndef __bip32_h
#define __bip32_h

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <nettle/ripemd160.h>

typedef struct bip32_key_t {
    bool public;

    union {
      uint8_t private[32];
      uint8_t public[64];
    } key;

    uint8_t chain[32];
    uint8_t parent_fingerprint[4];
    uint8_t depth;
    uint32_t index;
} bip32_key_t;

int bip32_key_init_private(bip32_key_t *ctx);
int bip32_key_init_from_entropy(bip32_key_t *bip32_key_ctx, uint8_t *entropy, size_t size);
int bip32_key_init_public_from_private_key(bip32_key_t *ctx, const bip32_key_t *private);
int bip32_key_p2pkh_address_from_key(const bip32_key_t *ctx, uint8_t *address, size_t *size);
int bip32_key_derive_child_key(const bip32_key_t *parent, uint32_t index, bip32_key_t *child);
int bip32_key_derive_child_by_path(const bip32_key_t *ctx, const char *path, bip32_key_t *child);
int bip32_key_serialize(bip32_key_t *ctx, bool encoded,
			uint8_t *result, size_t *size);
int bip32_key_deserialize(bip32_key_t *ctx, const char *encoded_key);
int bip32_key_to_wif(bip32_key_t *ctx, uint8_t *result, size_t *size);

typedef uint8_t bip32_key_identifier_t[RIPEMD160_DIGEST_SIZE];
int bip32_key_identifier_init_from_key(bip32_key_identifier_t ident, const bip32_key_t *key);
int bip32_key_identifier_fingerprint(const bip32_key_identifier_t ident, uint8_t *fingerprint);

#endif
