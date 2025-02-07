#include <string.h>
#include <nettle/hmac.h>
#include <nettle/sha2.h>

#include "utils.h"
#include "../external/libbase58/libbase58.h"
#include "bip32.h"

static int
_bip32_key_init(bip32_key_t *ctx, uint8_t *secret, uint8_t *chain,
                uint8_t depth, uint32_t index,
                uint8_t *fingerprint, bool public)
{
    memset(ctx, 0, sizeof(bip32_key_t));

    ctx->public = public;
    memcpy(ctx->key, secret, 32);
    memcpy(ctx->chain, chain, 32);
    ctx->depth = depth;
    ctx->index = index;
    memcpy(ctx->parent_fingerprint, fingerprint, 4);
    
    return 0;
}

int
bip32_key_init_from_entropy(bip32_key_t *ctx, uint8_t *entropy, size_t size)
{
    char *key = "Bitcoin seed";
    struct hmac_sha512_ctx hmac_sha512;

    if (size != 64)
        return -1;

    uint8_t mac[64];
    hmac_sha512_set_key(&hmac_sha512, strlen(key), (uint8_t *)key);
    hmac_sha512_update(&hmac_sha512, size, entropy);
    hmac_sha512_digest(&hmac_sha512, 64, mac);

    uint8_t *privkey = mac;
    uint8_t *chain = mac + 32;
    uint8_t fingerprint[] = { 0, 0, 0, 0 };
    uint32_t index = 0x00;
    
    return _bip32_key_init(ctx, privkey, chain, 0, index, fingerprint, false);
}

static inline int
_base58_checksum_encode(uint8_t *data, size_t size,
                        uint8_t *result, size_t *result_size)
{
    uint8_t hashed_xprv[SHA256_DIGEST_SIZE];
    struct sha256_ctx sha256;
    sha256_init(&sha256);
    sha256_update(&sha256, size, data);
    sha256_digest(&sha256, SHA256_DIGEST_SIZE, hashed_xprv);
    sha256_update(&sha256, SHA256_DIGEST_SIZE, hashed_xprv);
    sha256_digest(&sha256, SHA256_DIGEST_SIZE, hashed_xprv);

    memcpy(data + size, hashed_xprv, 4);
    return b58enc((char*)result, result_size, data, size + 4) ? 0 : -1;
}

int
bip32_key_serialize(bip32_key_t *ctx, bool private, bool encoded,
		    uint8_t *result, size_t *size)
{
    uint8_t buf[512] = { 0 };
    uint8_t version_private[4] = { 0x04, 0x88, 0xad, 0xe4 };
    uint8_t version_public[4] = { 0x04, 0x88, 0xb2, 0x1e };

    if (ctx->public && private)
        return -1;

    uint8_t *ptr = buf;
    memcpy(ptr, private ? version_private : version_public, 4);
    ptr += 4;

    *ptr = ctx->depth;
    ptr++;

    memcpy(ptr, ctx->parent_fingerprint, 4);
    ptr += 4;

    memcpy(ptr, &ctx->index, 4);
    ptr += 4;
    
    memcpy(ptr, ctx->chain, 32);
    ptr += 32;

    if (private)
    {
        *ptr = 0x00;
        memcpy(ptr+1, ctx->key, 32);
        ptr += 33;
    }
    else
    {
        // !!! FIXME !!!
    }

    if (!encoded)
    {
        memcpy(result, buf, ptr-buf);
        *size = ptr-buf;
        return 0;
    }
    else
    {
        return _base58_checksum_encode(buf, ptr - buf, result, size);
    }
    
    return 0;
}

static inline int
_base58_checksum_decode(const char *data, size_t size,
                       uint8_t *result, size_t *result_size)
{
  uint8_t hashed_xprv[SHA256_DIGEST_SIZE];
  struct sha256_ctx sha256;
  uint8_t checksum[4];

  if (b58tobin(result, result_size, data, size) == false)
    return -1;

  memcpy(checksum, result + (*result_size - 4), 4);
  *result_size -= 4;

  sha256_init(&sha256);
  sha256_update(&sha256, *result_size, result);
  sha256_digest(&sha256, SHA256_DIGEST_SIZE, hashed_xprv);
  sha256_update(&sha256, SHA256_DIGEST_SIZE, hashed_xprv);
  sha256_digest(&sha256, SHA256_DIGEST_SIZE, hashed_xprv);

  if (memcmp(checksum, hashed_xprv, 4) != 0)
    return -2;

  return 0;
}

int
bip32_key_deserialize(bip32_key_t *key, const char *encoded_key)
{
  uint8_t buf[4 + 1 + 4 + 4 + 32 + 1 + 32 + 4] = { 0 };
  size_t buf_size = sizeof(buf);
  uint8_t *pbuf = buf;

  uint8_t version_private[4] = { 0x04, 0x88, 0xad, 0xe4 };
  uint8_t version_public[4] = { 0x04, 0x88, 0xb2, 0x1e };

  if (_base58_checksum_decode(encoded_key, strlen(encoded_key), buf, &buf_size) != 0)
    return -1;

  memset(key, 0, sizeof(bip32_key_t));

  // verify key version
  if (memcmp(version_public, pbuf, 4) == 0)
    key->public = true;
  else if (memcmp(version_private, pbuf, 4) == 0)
    key->public = false;
  else return -2;
  pbuf += 4;

  // get depth
  key->depth = *pbuf;
  pbuf++;

  // get parent key fingerprint
  memcpy(key->parent_fingerprint, pbuf, 4);
  pbuf += 4;

  // get index
  memcpy((uint8_t *)&key->index, pbuf, 4);
  pbuf += 4;

  // get chain
  memcpy(key->chain, pbuf, 32);
  pbuf += 32;

  // if private key, skip over 0x00 byte padding
  if (!key->public)
    pbuf++;

  // get key from buf
  memcpy(key->key, pbuf, 32);
  return 0;
}

int
bip32_key_to_wif(bip32_key_t *ctx, uint8_t *result, size_t *size)
{
    uint8_t buf[512] = { 0 };

    if (ctx->public)
        return 1;

    uint8_t *ptr = buf;
    *ptr = 0x80;
    ptr++;
    memcpy(ptr, ctx->key, 32);
    ptr += 32;
    *ptr = 0x01;
    ptr++;

    return _base58_checksum_encode(buf, ptr - buf, result, size);
}
