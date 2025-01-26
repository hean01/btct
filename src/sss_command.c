#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>

#include "command.h"
#include "bip32.h"
#include "sss.h"

#include "../external/libbase58/libbase58.h"

static int
_sss_create(uint8_t share_cnt, uint8_t threshold)
{
  char buf[1024];
  size_t size = 1024;
  uint8_t tmp;
  size_t bytes=0;
  uint8_t data[sss_MLEN]={0};
  sss_Share shares[200];

  fprintf(stderr, "sss.create: creating %d share from secret with a recovery threshold of %d\n", share_cnt, threshold);

  // Read secret from stdin
  freopen(NULL, "rb", stdin);
  bytes = fread(data, 1, sss_MLEN, stdin);
  if (bytes == 64 && fread(&tmp, 1, 1, stdin) == 1) {
    fprintf(stderr, "sss.create: the secret length is more than %ld bytes, aborting...\n", sss_MLEN);
    return EXIT_FAILURE;
  }

  fprintf(stderr, "sss.create: read %ld bytes (%ld bits) of secret from stdin\n", bytes, bytes*8);

  // create shares
  memset(shares, 0, sizeof(shares));
  sss_create_shares(shares, data, 200, threshold);

  // dump shares to stdout
  fprintf(stderr, "sss.create: dumping %d shares to stdout in base58\n", share_cnt);

  for (size_t s=0; s < share_cnt; s++) {
    size = sizeof(buf);
    b58enc(buf, &size, shares[rand() % 200], sizeof(sss_Share));
    fprintf(stdout, "%s\n", buf);
  }

  return EXIT_SUCCESS;
}

static void
_sss_create_usage(void)
{
  fputs("usage: btct sss.create <args>\n", stderr);
  fputs("\n", stderr);
  fputs("  -s, --shares=<cnt>      Specify the amount of shares to splite the input into,\n"
        "                          default value is 3 shares.\n", stderr);
  fputs("  -t, --threshold=<cnt>   Specify the threshold of number of shares required for\n"
        "                          recover the secret, default value is 2 shares.\n",stderr);
  fputs("\n", stderr);

  fputs("examples:\n", stderr);
  fputs("\n", stderr);
  fputs("  Create HD Wallet and split the master key into 5 shares with a threshold of 3 keys for recover the key.\n", stderr);
  fputs("\n", stderr);
  fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' | \\\n", stderr);
  fputs("        btct bip39.seed --passphrase=TREZOR | \\\n", stderr);
  fputs("        btct bip32.masterkey | btct sss.create --shares=5 --thresholds=3\n", stderr);
  fputs("\n", stderr);
}

static int
_sss_recover(void)
{
  uint8_t out[sss_MLEN];
  char *buf[256] = {NULL};
  size_t length;
  uint8_t share_cnt = 0;
  sss_Share *shares;

  // Read share from stdin
  while(getline(&buf[share_cnt], &length, stdin) != -1) {
    share_cnt++;
    if (share_cnt == 255) {
      fputs("To many shares read from stdin\n", stderr);
      return EXIT_FAILURE;
    }
  }
  fprintf(stderr, "sss.recover: %d shares read from stdin\n", share_cnt);

  // Decode base58 shares into binary shares to recover from
  shares = malloc(sizeof(sss_Share) * share_cnt);
  for (int s = 0; s < share_cnt; s++) {
    length = sizeof(sss_Share);
    if (b58tobin((sss_Share *)shares[s], &length, buf[s], strlen(buf[s])-1) == false) {
      fputs("sss.recover: Failed to decode base58 encoded share\n", stderr);
      return EXIT_FAILURE;
    }
  }

  // Recover secret from shares
  if (sss_combine_shares(out, (const sss_Share *)shares, share_cnt) != 0) {
    fputs("sss.recover: failed to recover secret from shares\n", stderr);
    return EXIT_FAILURE;
  }

  fwrite(out, sizeof(out), 1, stdout);
  return EXIT_SUCCESS;
}

static void
_sss_recover_usage(void)
{
  fputs("usage: btct sss.recover <args>\n", stderr);
  fputs("\n", stderr);

  fputs("examples:\n", stderr);
  fputs("\n", stderr);
  fputs("  Create three shares of a secret menomic seed with a threshold of two: \n", stderr);
  fputs("\n", stderr);
  fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' | \\\n", stderr);
  fputs("        btct sss.create --shares=3 --thresholds=2\n", stderr);
  fputs("\n", stderr);
}


static int
_sss_create_command(int argc, char **argv) {
  int c;
  uint8_t shares = 3;
  uint8_t threshold = 2;

  while (1)
    {
      int option_index = 0;
      static struct option long_options[] = {
        {"help",  no_argument, 0, 'h' },
        {"shares",  required_argument, 0, 's' },
        {"thresholds", required_argument, 0, 't' },
        {0, 0, 0, 0}
      };

      c = getopt_long(argc, argv, "hst", long_options, &option_index);
      if (c == -1)
        break;

      switch (c) {
      case 'h':
        _sss_create_usage();
        return EXIT_FAILURE;

      case 's':
        shares = atoi(optarg);
        break;

      case 't':
        threshold = atoi(optarg);
        break;
      }
    }

  return _sss_create(shares, threshold);
}

static int
_sss_recover_command(int argc, char **argv) {
  int c;
  while (1)
    {
      int option_index = 0;
      static struct option long_options[] = {
        {"help",  no_argument, 0, 'h' },
        {0, 0, 0, 0}
      };

      c = getopt_long(argc, argv, "h", long_options, &option_index);
      if (c == -1)
        break;

      switch (c) {
      case 'h':
        _sss_recover_usage();
        return EXIT_FAILURE;
      }
    }

  return _sss_recover();
}

static void _sss_command_usage(void)
{
  fputs("usage: btct sss.<command> <args>\n", stderr);
  fputs("\n", stderr);
  fputs("Shamir Secret Sharing (SSS) is used to secure a secret in a distributed form, most often to secure "
        "encryption keys. The secret is split into multiple shares, which individually do not give any "
        "information about the secret. "
        "To reconstruct a secret secured by SSS, a number of shares is needed, called the threshold. No "
        "information about the secret can be gained from any number of shares below the threshold (a property "
        "called perfect secrecy).\n",stderr);
  fputs("\n\n", stderr);
  fputs("commands:\n", stderr);
  fputs("\n", stderr);
  fputs("  create       Create shares from your secret\n", stderr);
  fputs("  recover      Combine a number of shares to recover secret\n", stderr);
  fputs("\n\n",stderr);
  fputs("examples:\n", stderr);
  fputs("\n",stderr);
  fputs("  Generate bip32 serialized HD wallet master key and then split it into three shares with the ability to recover using only two of the three shares:\n",stderr);
  fputs("\n",stderr);
  fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' | \\\n", stderr);
  fputs("        btct bip39.seed --passphrase=TREZOR | \\\n", stderr);
  fputs("        btct sss.create --shares=3 --threshold=2\n", stderr);
  fputs("\n", stderr);
}

int sss_command(int argc, char **argv)
{
  int res;

  struct command_t commands[] = {
    { "sss.create", _sss_create_command },
    { "sss.recover", _sss_recover_command },
    { NULL, NULL, }
  };

  res = command_dispatch(commands, argv[0], false, argc, argv);
  if (res == -1)
    _sss_command_usage();

  return (res != EXIT_SUCCESS ? EXIT_FAILURE : EXIT_SUCCESS);
}
