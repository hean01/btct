#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>

#include "command.h"
#include "bip32.h"

static int
_bip32_master_key(bool encode)
{
    uint8_t seed[128]={0};
    size_t bytes = 0;

    // Read entrophy bits from stdin
    freopen(NULL, "rb", stdin);
    while (fread(seed + bytes, 1, 1, stdin))
        bytes++;

    fprintf(stderr,"read %ld bits of seed from stdin to use for creating hierarchical deterministic master key\n", bytes*8);

    char buffer[4096];
    size_t size = sizeof(buffer);

    bip32_key_t ctx;
    bip32_key_init_from_entropy(&ctx, seed, bytes);
    bip32_key_to_extended_key(&ctx, true, encode, (uint8_t*)buffer, &size);

    freopen(NULL, "wb", stdout);
    fwrite(buffer, 1, size, stdout);
    if (encode)
        fputs("\n", stdout);

    return EXIT_SUCCESS;
}

static void
_bip32_master_key_usage()
{
    fputs("usage: btct bip32.masterkey <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  -p, --plain          Do not perform base58 encoding of key\n", stderr);
    fputs("\n", stderr);
    fputs("examples:\n", stderr);
    fputs("\n", stderr);
    fputs("  Create a HD wallet master key from mnemonics and generate a QR code:\n", stderr);
    fputs("\n", stderr);
    fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' | \\\n", stderr);
    fputs("        btct bip39.seed --passphrase=TREZOR | \\\n", stderr);
    fputs("        btct bip32.masterkey | qrencode -lH -o - -t ANSI256\n", stderr);
    fputs("\n", stderr);
}

static int
_bip32_master_key_command(int argc, char **argv)
{
    int c;
    bool encode = true;
    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {"plain",  no_argument, 0, 'p' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "h", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                _bip32_master_key_usage();
                return EXIT_FAILURE;

            case 'p':
                encode = false;
                break;
        }
    }

    return _bip32_master_key(encode);
}


static void _bip32_command_usage()
{
    fputs("usage: btct bip39.<command> <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  master_key       Generate hierarchical deterministic master key\n", stderr);
    fputs("\n",stderr);
    fputs("examples:\n", stderr);
    fputs("\n",stderr);
    fputs("  Generate bip32 serialized HD wallet master key from mnemonics:\n",stderr);
    fputs("\n",stderr);
    fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' | \\\n", stderr);
    fputs("        btct bip39.seed --passphrase=TREZOR | \\\n", stderr);
    fputs("        btct bip32.masterkey\n", stderr);
    fputs("\n", stderr);
}

int bip32_command(int argc, char **argv)
{
    int res;

    struct command_t commands[] = {
        { "bip32.masterkey", _bip32_master_key_command },
        { NULL, NULL, }
    };

    res = command_dispatch(commands, argv[0], false, argc, argv);
    if (res == -1)
        _bip32_command_usage();

    return (res != EXIT_SUCCESS ? EXIT_FAILURE : EXIT_SUCCESS);
}
