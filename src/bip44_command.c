#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>

#include "command.h"
#include "bip44.h"

static int _bip44_account(uint32_t account_nr, char *coin_symbol)
{
  bip32_key_t key, account_key;
  uint8_t buf[4096]={0};
  size_t bytes = 0;
  bip44_coin_t *coin;

  coin = bip44_coin_by_symbol(coin_symbol);
  if (coin == NULL)
  {
    fprintf(stderr, "bip44.account: symbol '%s' not found in coin table\n", coin_symbol);
    return EXIT_FAILURE;
  }

  freopen(NULL, "rb", stdin);
  while (fread(buf + bytes, 1, 1, stdin))
    bytes++;

  if (buf[bytes-1] == '\n') {
    buf[bytes-1] = '\0';
    bytes--;
  }

  if (bip32_key_deserialize(&key, buf) != 0)
  {
    fputs("bip44.account: failed to deserialize key from stdin\n", stderr);
    return EXIT_FAILURE;
  }

  if (key.public == true)
  {
    fputs("bip44.account: failed, read private key is a public key\n", stderr);
    return EXIT_FAILURE;
  }

  if (bip44_create_account(&key, coin, account_nr, &account_key) != 0)
  {
    fputs("bip44.account: failed, read create account private key\n", stderr);
    return EXIT_FAILURE;
  }

  bytes = sizeof(buf);
  bip32_key_serialize(&account_key, true, buf, &bytes);
  fprintf(stdout, "%s\n", buf);
  return EXIT_SUCCESS;
}

static void
_bip44_account_command_usage(void)
{
  fputs("usage: btct bip44.account <args>\n", stderr);
  fputs("\n", stderr);
  fputs("  -a, --account <count>  Specify which account number to derive a key for, default\n", stderr);
  fputs("                         account is #0.\n", stderr);
  fputs("  -c, --coin <symbol>    Specify coin symbol for specific coin type, default is 'BTC'\n", stderr);
  fputs("\n", stderr);
  fputs("  Generate account #2 for BTC\n", stderr);
  fputs("\n", stderr);
  fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' \\\n",stderr);
  fputs("          | btct bip39.seed --passphrase=TREZOR \\\n", stderr);
  fputs("          | btct bip32.masterkey\\\n", stderr);
  fputs("          | btct bip44.account --account=2 --coin=BTC\n", stderr);
  fputs("\n", stderr);
}

static  int
_bip44_account_command(int argc, char **argv)
{
  int c;
  int account_nr = 0;
  char *coin_symbol = "BTC";

  while (1)
    {
      int option_index = 0;
      static struct option long_options[] = {
        {"help",  no_argument, 0, 'h' },
        {"account",  required_argument, 0, 'a' },
        {"coin",  required_argument, 0, 'c' },
        {0, 0, 0, 0}
      };

      c = getopt_long(argc, argv, "ha:c:", long_options, &option_index);
      if (c == -1)
        break;

      switch (c) {
      case 'h':
        _bip44_account_command_usage();
        return EXIT_FAILURE;

      case 'a':
        account_nr = atoi(optarg);
        break;

      case 'c':
        coin_symbol = optarg;
        break;
      }
    }

  return _bip44_account(account_nr, coin_symbol);
}

static void _bip44_command_usage(void)
{
  fputs("usage: btct bip44.<command> <args>\n", stderr);
  fputs("\n", stderr);
  fputs("  account         Generate a bip44 account for specified coin from encoded masterkey\n", stderr);
  fputs("                  read on stdin.\n", stderr);
  fputs("\n",stderr);
  fputs("examples:\n", stderr);
  fputs("\n",stderr);
  fputs("  Generate bip44 account #1 for XRP coin:\n",stderr);
  fputs("\n",stderr);
  fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' \\\n", stderr);
  fputs("        | btct bip39.seed --passphrase=TREZOR \\\n", stderr);
  fputs("        | btct bip32.masterkey \\\n", stderr);
  fputs("        | btct bip44.account -a 0 -c XRP\n", stderr);
  fputs("\n", stderr);
}

int bip44_command(int argc, char **argv)
{
  int res;

  struct command_t commands[] = {
    { "bip44.account", _bip44_account_command },
    { NULL, NULL, }
  };

  res = command_dispatch(commands, argv[0], false, argc, argv);
  if (res == -1)
    _bip44_command_usage();

  return (res != EXIT_SUCCESS ? EXIT_FAILURE : EXIT_SUCCESS);
}
