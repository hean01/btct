#ifndef __bip85_h__
#define __bip85_h__

#include <stdint.h>
#include "bip32.h"

int bip85_entropy_from_key(const bip32_key_t *key, const char *subpath, uint8_t *entropy);
int bip85_application_bip39(const bip32_key_t *key, uint32_t language, uint32_t word_cnt, uint32_t index,
                            char ***result, size_t *result_cnt);
#endif
