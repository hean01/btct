#include <string.h>
#include <nettle/hmac.h>

#include "../external/libbase58/libbase58.h"

#include "bip39.h"
#include "bip85.h"

int
bip85_entropy_from_key(const bip32_key_t *master_key, const char *subpath, uint8_t *entropy)
{
  bip32_key_t child;
  char bip85_path[256];  
  struct hmac_sha512_ctx hmac_sha512;
  const char *key = "bip-entropy-from-k";
  
  if (master_key->public == true)
    return -1;

  snprintf(bip85_path, sizeof(bip85_path), "m/83696968'/%s", subpath);
  if (bip32_key_derive_child_by_path(master_key, bip85_path, &child) != 0)
    return -2;

  hmac_sha512_set_key(&hmac_sha512, strlen(key), (uint8_t*)key);
  hmac_sha512_update(&hmac_sha512, sizeof(child.key.private), child.key.private);
  hmac_sha512_digest(&hmac_sha512, 64, entropy);  

  return 0;
}

int
bip85_application_bip39(const bip32_key_t *key, uint32_t language, uint32_t word_cnt, uint32_t index,
                            char ***result, size_t *result_cnt)
{
  bip39_t bip39;
  char buf[1024] = {0};
  uint8_t entropy[512] = {0};
  size_t entropy_bits;

  if (word_cnt == 12) entropy_bits = 128;
  else if (word_cnt == 15) entropy_bits = 160;
  else if (word_cnt == 18) entropy_bits = 192;
  else if (word_cnt == 21) entropy_bits = 224;
  else if (word_cnt == 24) entropy_bits = 256;
  else return -1;

  // only suport for english bip39
  if (language != 0)
    return -2;

  // derive entropy for bip39 seed phrase
  snprintf(buf, sizeof(buf), "39'/%d'/%d'/%d'", language, word_cnt, index);
  if (bip85_entropy_from_key(key, buf, &entropy) != 0)
    return -3;

  bip39_init(&bip39);  
  if (bip39_to_mnemonics(&bip39, entropy, entropy_bits, result, result_cnt) != 0)
    return -4;

  return 0;
}

int
bip85_application_pwd_base85(const bip32_key_t *key, uint32_t length, uint32_t index, char *result)
{
  char buf[1024] = {0};
  size_t buf_size = sizeof(buf);
  uint8_t entropy[512] = {0};

  snprintf(buf, buf_size, "707785'/%d'/%d'", length, index);
  if (bip85_entropy_from_key(key, buf, &entropy) != 0)
    return -1;

  if (utils_base85_encode(entropy, 64, buf) != 0)
    return -2;

  strncat(result, buf, length);
  return 0;
}
