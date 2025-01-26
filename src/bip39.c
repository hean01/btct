#include <stdio.h>
#include <string.h>

#include "bip39.h"
#include "bip39_english.h"

int bip39_init(bip39_t *ctx)
{
    memset(ctx, 0, sizeof(bip39_t));
    return 0;
}

static inline uint16_t
_read_11bit_value_at_bit_index(uint8_t *seed, size_t bit_index) {
    uint32_t value = 0;
    uint8_t byte_index = bit_index / 8;
    uint16_t bit_offset = bit_index - (byte_index * 8);
    uint8_t *pseed = seed + byte_index;
    value = pseed[0] << 24 | pseed[1] << 16 | pseed[2] << 8 | pseed[1];
    value = value >> (32 - bit_offset - 11);
    value = value & 0x7ff;
    return value;
}

int bip39_to_mnemonics(bip39_t *ctx, uint8_t *entropy, size_t bits,
                       char ***mnemonics, size_t *mnemonic_count)
{
    uint8_t bytes = bits / 8;
    uint8_t checksum_size = bits / 32;

    if (!(128 <= bits && bits <= 256))
        return 1;

    uint8_t digest[4] = {0};
    sha256_init(&ctx->sha256);
    sha256_update(&ctx->sha256, bytes, entropy);
    sha256_digest(&ctx->sha256, 4, digest);

    uint8_t *seed=malloc(bytes+2);
    memcpy(seed, entropy, bytes);
    seed[bytes] = digest[0];
    seed[bytes + 1] = digest[1];

    *mnemonic_count = (bits + checksum_size) / 11;
    *mnemonics = malloc(sizeof(char *) * *mnemonic_count);
    uint16_t bit_index = 0;
    for (size_t word = 0; word < *mnemonic_count; word++) {
        (*mnemonics)[word] = (char *)bip39_english[_read_11bit_value_at_bit_index(seed, bit_index)];
        bit_index += 11;
    }

    free(seed);
    return 0;
}

int bip39_to_seed(bip39_t *ctx, const uint8_t *mnemonic, size_t mnemonic_size,
                  int iterations, const uint8_t *passphrase,
                  uint8_t *seed)
{
    uint8_t salt[4096] = "mnemonic";

    if (passphrase != NULL)
        strncat((char*)salt, (char*)passphrase, strlen((char*)passphrase));

    pbkdf2_hmac_sha512(mnemonic_size, mnemonic, iterations, strlen((char*)salt), salt, 64, seed);
    return 0;
}

