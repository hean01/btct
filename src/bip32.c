#include <string.h>
#include <nettle/hmac.h>
#include <nettle/sha2.h>

#include "utils.h"
#include "../external/libbase58/libbase58.h"
#include "bip32.h"

int
bip32_init(bip32_t *ctx, bool testnet)
{
    memset(ctx, 0, sizeof(bip32_t));
    ctx->testnet = testnet;
    return 0;
}

int
bip32_master_key_from_seed(bip32_t *ctx, uint8_t *seed, size_t seed_size,
                           char *result, size_t *size)
{
    char *key = "Bitcoin seed";
    struct hmac_sha512_ctx hmac_sha512;

    if (seed_size != 64)
        return -1;

    uint8_t mac[64];
    hmac_sha512_set_key(&hmac_sha512, strlen(key), (uint8_t *)key);
    hmac_sha512_update(&hmac_sha512, seed_size, seed);
    hmac_sha512_digest(&hmac_sha512, 64, mac);

    uint8_t xprv[512] = { 0 };
    uint8_t mainnet_private_magic[4] = { 0x04, 0x88, 0xad, 0xe4 };
    uint8_t testnet_private_magic[4] = { 0x04, 0x35, 0x83, 0x94 };

    uint8_t *ptr = xprv;

    // Write magic
    if (ctx->testnet)
        memcpy(ptr, testnet_private_magic, sizeof(testnet_private_magic));
    else
        memcpy(ptr, mainnet_private_magic, sizeof(mainnet_private_magic));
    ptr+=4;

    // Depth
    ptr++;

    // Parent fingerprint
    ptr += 4;

    // Child
    ptr += 4;

    // Chain code 256bit
    memcpy(ptr, mac + 32, 32);
    ptr += 32;

    // Private key 256bit
    memcpy(ptr + 1, mac, 32);
    ptr += 33;

    // calculate double hash of xprv
    uint8_t hashed_xprv[SHA256_DIGEST_SIZE];
    struct sha256_ctx sha256;
    sha256_init(&sha256);
    sha256_update(&sha256, (ptr - xprv), xprv);
    sha256_digest(&sha256, SHA256_DIGEST_SIZE, hashed_xprv);
    sha256_update(&sha256, SHA256_DIGEST_SIZE, hashed_xprv);
    sha256_digest(&sha256, SHA256_DIGEST_SIZE, hashed_xprv);
    
    // append 4 bytes checksum
    memcpy(ptr, hashed_xprv, 4);
    ptr+=4;

    return b58enc(result, size, xprv, ptr - xprv) ? 0 : -1;
}
