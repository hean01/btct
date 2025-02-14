#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include <limits.h>
#include <inttypes.h>
#include <getopt.h>

#include "command.h"
#include "bip32.h"
#include "bip39.h"

static
int _input(const char *prompt, bool echo, char *result, size_t size)
{
  int res;
  struct termios term;

  if (!echo) {
    tcgetattr(fileno(stdin), &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), 0, &term); 
  }

  fprintf(stderr, "%s: ", prompt);
  freopen(NULL, "rb", stdin);
  
  res = fgets(result, size, stdin);
  if (!echo) {
    term.c_lflag |= ECHO;
    tcsetattr(fileno(stdin), 0, &term);
    fputs("\n", stderr);
  }

  return res;
}


static int
_store_init(const char *filename)
{
  bip32_key_t key;
  bip39_t bip39;
  uint8_t seed[10][32] = {0};
  char buf[4096] = {0};
  char password[512] = {0};
  char **mnemonics;
  size_t mnemonics_cnt;

  int h = open("/dev/urandom", O_RDONLY);
  for (size_t i = 0; i < 10; i++)
    read(h, seed[i], sizeof(seed) / 10);
  close(h);

  bip39_init(&bip39);

  fputs("Here follows a list of 10 seeds from /dev/urandom, choose any of them by the number\n"
        "when prompt to be stored and used.\n"
        "\n"
        , stdout);

  // Present 10 mnemonics to choose one of to use
  for (size_t i = 0; i < 10; i++) {
    // generate mnemonics to save to store
    if (bip39_to_mnemonics(&bip39, seed[i], (sizeof(seed) / 10) * 8, &mnemonics, &mnemonics_cnt) != 0)
      return EXIT_FAILURE;

    fprintf(stdout, " %2ld: " , 1+i);
    for (size_t i = 0; i < mnemonics_cnt; i++) {
      if (i != 0 && i % 8 == 0) fputs("\n     ", stdout);

      fputs(mnemonics[i], stdout);
      
      if (i != (mnemonics_cnt - 1))
        fputs(" ", stdout);
    }
    fputs("\n\n", stdout);
  }

  // prompt for choice
 redo_prompt:
  char *tmp;
  _input("Enter the number of seed to use", true, buf, sizeof(buf));
  long choice = atoi(buf);
  if (choice == 0)
    goto redo_prompt;

  // prompt for password
  _input("Enter password for store", false, password, sizeof(password));

  if (store_write_seed(filename, password, seed[choice-1], sizeof(seed[choice-1])) != 0)
  {
    fprintf(stderr, "failed to store into file %s\n", filename);
    return EXIT_FAILURE;
  }
  
  return EXIT_SUCCESS;
}

static void
_store_init_command_usage(void)
{
    fputs("usage: btct store.init <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  -f, --file <filename>   Specify a file for the encrypted store with generated wallets.\n", stderr);
    fputs("                          Default store file is ~/btct_store.dat.\n", stderr);
    fputs("\n", stderr);
    fputs("examples:\n", stderr);
    fputs("\n", stderr);
    fputs("  Create a random seed of 16 bytes eg. 256 bits seed, generate mnemonics and save to store\n", stderr);
    fputs("\n", stderr);
    fputs("      head -c32 /dev/urandom \\\n", stderr);
    fputs("          | btct bip39.mnemonics --sentence \\\n", stderr);
    fputs("          | btct store.init", stderr);
    fputs("\n", stderr);
}

static int
_store_init_command(int argc, char **argv)
{
    int c;
    const char *filename = NULL;

    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {"filename",  no_argument, 0, 'f' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hf:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                _store_init_command_usage();
                return EXIT_FAILURE;

            case 'f':
                filename = optarg;
                break;
        }
    }

    return _store_init(filename);
}

static int
_store_read(const char *filename)
{
  char seed[256] = {0};
  size_t size = sizeof(seed);
  char password[256]={0};

  // prompt for password
  _input("Enter password for store", false, password, sizeof(password));

  if (store_read_seed(filename, password, seed, size) != 0)
    return EXIT_FAILURE;

  fwrite(seed, 32, 1, stdout);
  
  return EXIT_SUCCESS;
}

static void
_store_read_command_usage(void)
{
    fputs("usage: btct store.read <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  -f, --file <filename>   Specify a file for the encrypted store to read from.\n", stderr);
    fputs("                          Default store file is ~/.btct.dat.\n", stderr);
    fputs("\n", stderr);
    fputs("examples:\n", stderr);
    fputs("\n", stderr);
    fputs("  Create a random seed of 16 bytes eg. 256 bits seed, generate mnemonics and save to store\n", stderr);
    fputs("\n", stderr);
    fputs("      btct store.read \\\n", stderr);
    fputs("          | btct bip32.masterkey\n", stderr);
    fputs("\n", stderr);
}

static int
_store_read_command(int argc, char **argv)
{
    int c;
    const char *filename = NULL;

    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {"filename",  no_argument, 0, 'f' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hf:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                _store_read_command_usage();
                return EXIT_FAILURE;

            case 'f':
                filename = optarg;
                break;
        }
    }

    return _store_read(filename);
}


static void _store_command_usage(void)
{
    fputs("usage: btct store.<command> <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  init            Initialize a new store, default ~/btct.dat\n", stderr);
    fputs("  read            Read mnemonics stored in file, default ~/btct.dat\n", stderr);
    fputs("\n",stderr);
    fputs("examples:\n", stderr);
    fputs("\n",stderr);
    fputs("  Generate a new store with a new seed:\n",stderr);
    fputs("\n",stderr);
    fputs("      head -c32 /dev/urandom \\\n", stderr);
    fputs("          | btct bip39.mnemonics --sentence \\\n", stderr);
    fputs("          | btct store.init", stderr);
    fputs("\n", stderr);
}

int store_command(int argc, char **argv)
{
    int res;

    struct command_t commands[] = {
        { "store.init", _store_init_command },
        { "store.read", _store_read_command },
        { NULL, NULL, }
    };

    res = command_dispatch(commands, argv[0], false, argc, argv);
    if (res == -1)
        _store_command_usage();

    return (res != EXIT_SUCCESS ? EXIT_FAILURE : EXIT_SUCCESS);
}
