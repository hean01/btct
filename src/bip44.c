#include <string.h>
#include <ctype.h>

#include "bip44.h"

bip44_coin_t *
bip44_coin_by_symbol(const char *symbol) {
  char *psym, *pbuf, buf[64]={0};
  pbuf = buf;
  psym = (char*)symbol;

  while (*psym != '\0') {
    *pbuf = toupper(*psym);
    psym++;
    pbuf++;
  }

  if (strlen(buf) == 0)
    return NULL;

  for (size_t i=0; i < sizeof(bip44_coins) / sizeof(bip44_coin_t); i++) {
    if (strcmp(bip44_coins[i].symbol, buf) == 0)
      return &bip44_coins[i];
  }

  return NULL;
}

int
bip44_create_account(const bip32_key_t *masterkey, const bip44_coin_t *coin, uint32_t account, bip32_key_t *accountkey)
{
  char path[1024];
  snprintf(path, sizeof(path), "m/44'/%d'/%d'", coin->type, account);
  if (bip32_key_derive_child_by_path(masterkey, path, accountkey) != 0)
    return -1;

  return 0;
}
