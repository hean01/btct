#include <string.h>
#include <nettle/hmac.h>
#include <nettle/sha2.h>
#include <nettle/ripemd160.h>

#include "utils.h"
#include "../external/libbase58/libbase58.h"
#include "../external/secp256k1/include/secp256k1.h"

#include "bip32.h"
#include "secp256k1.h"

static int
_bip32_key_init(bip32_key_t *ctx, uint8_t *secret, uint8_t *chain,
                uint8_t depth, uint32_t index,
                uint8_t *fingerprint, bool public)
{
    memset(ctx, 0, sizeof(bip32_key_t));

    ctx->public = public;
    memcpy(ctx->key.private, secret, 32);
    memcpy(ctx->chain, chain, 32);
    ctx->depth = depth;
    ctx->index = index;
    memcpy(ctx->parent_fingerprint, fingerprint, 4);
    
    return 0;
}

int
bip32_key_secp256k1_serialize_public_key(const bip32_key_t *ctx, bool compressed, uint8_t *result)
{
  struct secp256k1_context *secp256k1;
  size_t pubkey_size = compressed ? 33 : 65;

  if (ctx->public == false)
    return -1;

  secp256k1 = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  secp256k1_context_randomize(secp256k1, 0);
  secp256k1_ec_pubkey_serialize(secp256k1, result, &pubkey_size, &ctx->key.public, compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
  secp256k1_context_destroy(secp256k1);

  return 0;
}

int
bip32_key_init_private(bip32_key_t *ctx)
{
  memset(ctx, 0, sizeof(bip32_key_t));
  ctx->public = false;
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

int
bip32_key_init_public_from_private_key(bip32_key_t *ctx, const bip32_key_t *private)
{
  int res;
  struct secp256k1_context *secp256k1;
  struct secp256k1_pubkey pubkey;

  memcpy(ctx, private, sizeof(bip32_key_t));
  ctx->public = true;
  memset(ctx->key.public, 0, sizeof(ctx->key.public));

  secp256k1 = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (secp256k1_context_randomize(secp256k1, 0) != 1)
    return -1;

  if (secp256k1_ec_pubkey_create(secp256k1, &pubkey, private->key.private) != 1)
    return -2;

  memcpy(ctx->key.public, pubkey.data, sizeof(pubkey.data));

  secp256k1_context_destroy(secp256k1);
  return 0;
}

#define TWO_TO_POWER_OF_31 ((uint32_t)2<<30)

int
bip32_key_derive_child_key(const bip32_key_t *parent, uint32_t index, bip32_key_t *child) {
  struct hmac_sha512_ctx hmac_sha512;
  uint8_t mac[64];
  uint8_t zeros[10] = {0};
  uint8_t tmp[1024];

  memset(child, 0, sizeof(bip32_key_t));

  if (parent->public)
    return -1;

  hmac_sha512_set_key(&hmac_sha512, sizeof(parent->chain), parent->chain);

  if (index >= TWO_TO_POWER_OF_31)
  {
    // Create hardened child key
    uint8_t *ptmp = tmp;
    *ptmp = 0x00;
    ptmp++;

    memcpy(ptmp, parent->key.private, 32);
    ptmp += 32;

    utils_out_u32_be(ptmp, index);
    ptmp += 4;

    hmac_sha512_update(&hmac_sha512, ptmp - tmp, tmp);
  }
  else
  {
    // Create non hardened child key
    uint8_t *ptmp = tmp;

    // serialize parent public key into buffer

    bip32_key_t parent_public_key;
    bip32_key_init_public_from_private_key(&parent_public_key, parent);

    if (bip32_key_secp256k1_serialize_public_key(&parent_public_key, true, ptmp) != 0)
      return -2;
    ptmp += 33;

    // serialize index
    utils_out_u32_be(ptmp, index);
    ptmp += 4;

    hmac_sha512_update(&hmac_sha512, ptmp - tmp, tmp);
  }

  hmac_sha512_digest(&hmac_sha512, 64, mac);

  // copy chain to child key chain from right part of mac
  memcpy(child->chain, mac + 32, 32);

  size_t counter=0;
  char buf[256] = {0};
  mpz_t result, left, sec256k1_param_n, parent_key;

  mpz_init(left);
  mpz_import(left, 1, 1, 32, 1, 0, mac);
  mpz_init_set_str(sec256k1_param_n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
  mpz_init(parent_key);
  mpz_import(parent_key, 1, 1, 32, 1, 0, parent->key.private);

  mpz_init(result);
  mpz_add(result, left, parent_key);
  mpz_mod(result, result, sec256k1_param_n);
  mpz_export(child->key.private, &counter, 1, 32, 1, 0, result);

  child->public = false;
  child->depth = parent->depth + 1;
  child->index = index;

  bip32_key_identifier_t parent_key_ident;
  uint8_t parent_fingerprint[4];
  if (bip32_key_identifier_init_from_key(parent_key_ident, parent) != 0)
    return -2;
  if (bip32_key_identifier_fingerprint(parent_key_ident, child->parent_fingerprint) != 0)
    return -3;

  return 0;
}

int
bip32_key_derive_child_by_path(const bip32_key_t *ctx, const char *path, bip32_key_t *child)
{
  bip32_key_t tmp, *current = ctx;
  bool hardened;
  uint32_t index;
  char *token,  buffer[512];
  snprintf(buffer, sizeof(buffer), path);

  // FIXME: for now only private key derive
  if (buffer[0] != 'm')
    return -1;

  token = strtok(buffer + 1, "/");
  current = ctx;
  while(token)
  {
    hardened = false;
    if (token[strlen(token) - 1] == '\'') {
      hardened = true;
      token[strlen(token) - 1] = '\0';
    }

    index = atoi(token);
    if (bip32_key_derive_child_key(current, hardened ? 0x80000000 + index : index, child) != 0)
      return -2;

    memcpy(&tmp, child, sizeof(bip32_key_t));
    current = &tmp;

    token = strtok(NULL, "/");
  }

  return 0;
}


static inline int
_base58_checksum_encode(uint8_t *data, size_t size,
                        uint8_t *result, size_t *result_size)
{
    uint8_t checksum[4];

    if (utils_sha256_checksum(data, size, checksum) != 0)
      return -1;

    memcpy(data + size, checksum, 4);

    return b58enc((char*)result, result_size, data, size + 4) ? 0 : -2;
}

int
bip32_key_serialize(bip32_key_t *ctx, bool encoded,
		    uint8_t *result, size_t *size)
{
    uint8_t buf[512] = { 0 };
    uint8_t version_private[4] = { 0x04, 0x88, 0xad, 0xe4 };
    uint8_t version_public[4] = { 0x04, 0x88, 0xb2, 0x1e };

    uint8_t *ptr = buf;
    memcpy(ptr, ctx->public == true ? version_public : version_private, 4);
    ptr += 4;

    *ptr = ctx->depth;
    ptr++;

    memcpy(ptr, ctx->parent_fingerprint, 4);
    ptr += 4;

    utils_out_u32_be(ptr, ctx->index);
    ptr += 4;
    
    memcpy(ptr, ctx->chain, 32);
    ptr += 32;

    if (ctx->public == false)
    {
        *ptr = 0x00;
        memcpy(ptr+1, ctx->key.private, 32);
        ptr += 33;
    }
    else
    {
      if (bip32_key_secp256k1_serialize_public_key(ctx, true, ptr) != 0)
        return -1;
      ptr += 33;
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
  uint8_t checksum[4];
  uint8_t calculated_checksum[4];

  if (b58tobin(result, result_size, data, size) == false)
    return -1;

  memcpy(checksum, result + (*result_size - 4), 4);
  *result_size -= 4;

  if (utils_sha256_checksum(result, *result_size, calculated_checksum) != 0)
    return -2;

  if (memcmp(checksum, calculated_checksum, 4) != 0)
    return -3;

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
  key->index = utils_in_u32_be(pbuf);
  pbuf += 4;

  // get chain
  memcpy(key->chain, pbuf, 32);
  pbuf += 32;

  // get key
  if (key->public == false) {
    pbuf++;
    memcpy(key->key.private, pbuf, 32);
  }
  else
  {
    int res;
    struct secp256k1_context *secp256k1;
    struct secp256k1_pubkey pubkey;
    secp256k1 = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context_randomize(secp256k1, 0);
    if (secp256k1_ec_pubkey_parse(secp256k1, key->key.public, pbuf, 33) != 1)
      return -3;
    secp256k1_context_destroy(secp256k1);
  }

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
    memcpy(ptr, ctx->key.private, 32);
    ptr += 32;
    *ptr = 0x01;
    ptr++;

    return _base58_checksum_encode(buf, ptr - buf, result, size);
}


int
bip32_key_identifier_init_from_key(bip32_key_identifier_t ident, const bip32_key_t *key)
{
  bip32_key_t public_key;

  if (key->public == false)
  {
    if (bip32_key_init_public_from_private_key(&public_key, key) != 0)
      return -1;
  }
  else
    memcpy(&public_key, key, sizeof(bip32_key_t));

  memset(ident, 0, sizeof(bip32_key_identifier_t));

  // serialize public key
  uint8_t serialized_public_key[33];
  if (bip32_key_secp256k1_serialize_public_key(&public_key, true, serialized_public_key) != 0)
        return -2;

  if (utils_hash160(serialized_public_key, sizeof(serialized_public_key), ident) != 0)
    return -3;

  return 0;
}

int
bip32_key_identifier_fingerprint(const bip32_key_identifier_t ident, uint8_t *fingerprint)
{
  memcpy(fingerprint, ident, 4);
  return 0;
}

int
bip32_key_p2pkh_address_from_key(const bip32_key_t *ctx, uint8_t *address, size_t *size)
{
  uint8_t buf[256] = {0};
  bip32_key_t *public_key, tmp;

  public_key = ctx;

  // derive public key if private
  if (ctx->public == false)
  {
    if (bip32_key_init_public_from_private_key(&tmp, ctx) != 0)
      return -1;
    public_key = &tmp;
  }

  // serialize uncompressed public key
  uint8_t serialized_public_key[33]={0};
  if (bip32_key_secp256k1_serialize_public_key(public_key, true, serialized_public_key) != 0)
    return -2;

  if (utils_hash160(serialized_public_key, sizeof(serialized_public_key), buf + 1) != 0)
    return -3;

  // calculate checksum of extended key version:<pubkey>
  buf[0] = 0x00;
  if (utils_sha256_checksum(buf, 1 + RIPEMD160_DIGEST_SIZE, buf + 1 + RIPEMD160_DIGEST_SIZE) != 0)
    return -4;

  return b58enc((char*)address, size, buf, 1 + RIPEMD160_DIGEST_SIZE + 4) ? 0 : -5;
}
