#include "bip44_coins.h"
#include "bip32.h"

bip44_coin_t *bip44_coin_by_symbol(const char *symbol);

int bip44_create_account(const bip32_key_t *masterkey, const bip44_coin_t *coin, uint32_t account, bip32_key_t *accountkey);
