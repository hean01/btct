#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>

#include "command.h"
#include "bip85.h"

static int
_bip85_read_private_key_from_stdin(bip32_key_t *key)
{
  uint8_t buf[1024]={0};
  size_t bytes = 0;

  // read and deserialize private key from stdin
  freopen(NULL, "rb", stdin);
  while (fread(buf + bytes, 1, 1, stdin))
    bytes++;

  if (buf[bytes-1] == '\n') {
    buf[bytes-1] = '\0';
    bytes--;
  }

  if (bip32_key_deserialize(key, buf) != 0)
  {
    fputs("bip85.*: failed to deserialize key from stdin\n", stderr);
    return -1;
  }

  if (key->public == true)
  {
    fputs("bip85.*: failed, read private key is a public key\n", stderr);
    return -2;
  }

  return 0;
}

static int
_bip85_bip39(uint32_t language, uint32_t words, uint32_t index)
{
  bip32_key_t key;
  char **result = NULL;
  size_t result_count = 0;

  if (_bip85_read_private_key_from_stdin(&key) != 0)
    return EXIT_FAILURE;

  if (bip85_application_bip39(&key, language, words, index, &result, &result_count) != 0)
    return EXIT_FAILURE;
  
  for(size_t i = 0; i < result_count; i++) {
    fprintf(stdout, "%s", result[i]);
    if (i < result_count - 1)
      fputs(" ", stdout);
  }
  fputs("\n", stdout);
  
  return EXIT_SUCCESS;
}

static void
_bip85_bip39_command_usage(void)
{
  fputs("usage: btct bip85.bip39 <args>\n", stderr);
  fputs("\n", stderr);
  fputs("Generates a new bip39 mnemonics from derived entropy. Use this to create new deterministic\n", stderr);
  fputs("wallets from one seed due to the works of bip85.\n", stderr);
  fputs("\n", stderr);
  fputs("  -l, --language <index> Specify which language to use for  mnemonics , default\n", stderr);
  fputs("                         language is 0 (english).\n", stderr);
  fputs("  -w, --words <count>    Specify the amount of words to use, default is 12\n", stderr);
  fputs("  -i, --index <index>    Specify the index for the mnemonics, default is 0\n", stderr);
  fputs("\n", stderr);
  fputs("  Generate 24 words mnemonics for use with a hot wallet\n", stderr);
  fputs("\n", stderr);
  fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' \\\n",stderr);
  fputs("          | btct bip39.seed --passphrase=TREZOR \\\n", stderr);
  fputs("          | btct bip32.masterkey\\\n", stderr);
  fputs("          | btct bip85.bip39 --words=24 --index=100\n", stderr);
  fputs("\n", stderr);
}

static  int
_bip85_bip39_command(int argc, char **argv)
{
  int c;
  uint32_t language = 0;
  uint32_t word_cnt = 12;
  uint32_t index = 0;

  while (1)
    {
      int option_index = 0;
      static struct option long_options[] = {
        {"help",  no_argument, 0, 'h' },
        {"language",  required_argument, 0, 'l' },
        {"words",  required_argument, 0, 'w' },
        {"index",  required_argument, 0, 'i' },
        {0, 0, 0, 0}
      };

      c = getopt_long(argc, argv, "hl:w:i:", long_options, &option_index);
      if (c == -1)
        break;

      switch (c) {
      case 'h':
        _bip85_bip39_command_usage();
        return EXIT_FAILURE;

      case 'l':
        language = atoi(optarg);
        break;

      case 'w':
        word_cnt = atoi(optarg);
        break;

      case 'i':
        index = atoi(optarg);
        break;
      }
    }

  return _bip85_bip39(language, word_cnt, index);
}

static void
_bip85_pwd_base85_command_usage(void)
{
  fputs("usage: btct bip85.pwd_base85 <args>\n", stderr);
  fputs("\n", stderr);
  fputs("Generates a new password from deterministic entropy using base85 encoding.\n", stderr);
  fputs("\n", stderr);
  fputs("  -l, --length <length>  Specify the length of password, default is 12.\n", stderr);
  fputs("  -i, --index <index>    Specify the index for the password, default is 0\n", stderr);
  fputs("\n", stderr);
  fputs("  Generate a password with length 12 from index 1\n", stderr);
  fputs("\n", stderr);
  fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' \\\n",stderr);
  fputs("          | btct bip39.seed --passphrase=TREZOR \\\n", stderr);
  fputs("          | btct bip32.masterkey\\\n", stderr);
  fputs("          | btct bip85.pwd_base85 --length=12 --index=1\n", stderr);
  fputs("\n", stderr);
}

static int
_bip85_pwd_base85(uint32_t length, uint32_t index)
{
  bip32_key_t key;
  char buf[512];

  if (_bip85_read_private_key_from_stdin(&key) != 0)
    return EXIT_FAILURE;

  if (bip85_application_pwd_base85(&key, length, index, buf) != 0)
    return EXIT_FAILURE;

  fprintf(stdout, "%s\n", buf);

  return EXIT_SUCCESS;
}

static  int
_bip85_pwd_base85_command(int argc, char **argv)
{
  int c;
  uint32_t length = 12;
  uint32_t index = 0;

  while (1)
    {
      int option_index = 0;
      static struct option long_options[] = {
        {"help",  no_argument, 0, 'h' },
        {"length",  required_argument, 0, 'l' },
        {"index",  required_argument, 0, 'i' },
        {0, 0, 0, 0}
      };

      c = getopt_long(argc, argv, "hl:i:", long_options, &option_index);
      if (c == -1)
        break;

      switch (c) {
      case 'h':
        _bip85_pwd_base85_command_usage();
        return EXIT_FAILURE;

      case 'l':
        length = atoi(optarg);
        break;

      case 'i':
        index = atoi(optarg);
        break;
      }
    }

  return _bip85_pwd_base85(length, index);
}

static void
_bip85_hd_seed_wif_command_usage(void)
{
  fputs("usage: btct bip85.hd_seed_wif <args>\n", stderr);
  fputs("\n", stderr);
  fputs("Generates a HD Seed WIF from deterministic entropy for Bitcoin Core wallets.\n", stderr);
  fputs("\n", stderr);
  fputs("  -i, --index <index>    Specify the index for the password, default is 0\n", stderr);
  fputs("\n", stderr);
  fputs("  Generate HD Seed WIF wallet using index 2\n", stderr);
  fputs("\n", stderr);
  fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' \\\n",stderr);
  fputs("          | btct bip39.seed --passphrase=TREZOR \\\n", stderr);
  fputs("          | btct bip32.masterkey\\\n", stderr);
  fputs("          | btct bip85.hd_seed_wif --index=2\n", stderr);
  fputs("\n", stderr);
}

static int
_bip85_hd_seed_wif(uint32_t index)
{
  bip32_key_t key;
  char buf[512];
  size_t size;

  if (_bip85_read_private_key_from_stdin(&key) != 0)
    return EXIT_FAILURE;

  if (bip85_application_hd_seed_wif(&key, index, buf, &size) != 0)
    return EXIT_FAILURE;

  fprintf(stdout, "%s\n", buf);

  return EXIT_SUCCESS;
}

static int
_bip85_hd_seed_wif_command(int argc, char **argv)
{
  int c;
  uint32_t index = 0;

  while (1)
    {
      int option_index = 0;
      static struct option long_options[] = {
        {"help",  no_argument, 0, 'h' },
        {"index",  required_argument, 0, 'i' },
        {0, 0, 0, 0}
      };

      c = getopt_long(argc, argv, "hi:", long_options, &option_index);
      if (c == -1)
        break;

      switch (c) {
      case 'h':
        _bip85_hd_seed_wif_command_usage();
        return EXIT_FAILURE;

      case 'i':
        index = atoi(optarg);
        break;
      }
    }

  return _bip85_hd_seed_wif(index);
}

static void _bip85_command_usage(void)
{
  fputs("usage: btct bip85.<command> <args>\n", stderr);
  fputs("\n", stderr);
  fputs("  bip39           Derive a deterministic mneonmic seed phrase.\n", stderr);
  fputs("  hd_seed_wif     Derive a HD Seed for Bitcoin Core wallets.\n", stderr);
  fputs("  pwd_base85      Derive a deterministic password.\n", stderr);
  fputs("\n",stderr);
  fputs("examples:\n", stderr);
  fputs("\n",stderr);
  fputs("  Derive a deterministics mnenomic seed phrase, english, 12 words:\n",stderr);
  fputs("\n",stderr);
  fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' \\\n", stderr);
  fputs("        | btct bip39.seed --passphrase=TREZOR \\\n", stderr);
  fputs("        | btct bip32.masterkey \\\n", stderr);
  fputs("        | btct bip85.bip39 \n", stderr);
  fputs("\n", stderr);
}

int bip85_command(int argc, char **argv)
{
  int res;

  struct command_t commands[] = {
    { "bip85.bip39", _bip85_bip39_command },
    { "bip85.pwd_base85", _bip85_pwd_base85_command },
    { "bip85.hd_seed_wif", _bip85_hd_seed_wif_command },
    { NULL, NULL, }
  };

  res = command_dispatch(commands, argv[0], false, argc, argv);
  if (res == -1)
    _bip85_command_usage();

  return (res != EXIT_SUCCESS ? EXIT_FAILURE : EXIT_SUCCESS);
}
