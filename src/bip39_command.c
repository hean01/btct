#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>

#include "command.h"
#include "bip39.h"


typedef enum _mnemonics_format_e {
    SENTENCE,
    PRETTY
} _mnemonics_format_t;

static int _bip39_to_mnemonics(_mnemonics_format_t format)
{
    uint8_t seed[128]={0};
    size_t bytes = 0;

    // Read entrophy bits from stdin
    freopen(NULL, "rb", stdin);
    while (fread(seed + bytes, 1, 1, stdin))
        bytes++;

    fprintf(stderr, "bip39.mnemonics: read %ld bits of entrophy seed from stdin\n", bytes*8);

    bip39_t ctx;
    if (bip39_init(&ctx) != 0) {
        fprintf(stderr, "bip39.mnemonics: failed to initialize bip39 context\n");
        return EXIT_FAILURE;
    }

    char **words = NULL;
    size_t word_count = 0;
    if (bip39_to_mnemonics(&ctx, seed, bytes*8, &words, &word_count) != 0) {
        fprintf(stderr, "bip39.mnemonics: failed to generate mnemonics from seed\n");
        return EXIT_FAILURE;
    }

    for (size_t w = 0; w < word_count; w++)
    {
        switch (format)
        {

        case SENTENCE:
            fprintf(stdout, "%s", words[w]);
            if (w < word_count - 1)
                fputs(" ", stdout);
            break;

        case PRETTY:
        default:
            fprintf(stdout, "%ld: %s\n", 1 + w, words[w]);
            break;
        }
    }

    fputs("\n", stdout);
    free(words);

    return EXIT_SUCCESS;
}

static void
_bip39_mnemonics_command_usage()
{
    fputs("usage: btct bip39.mnemonics <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  -s, --sentence          Output mnemonics as a sentence on one line, use as input\n", stderr);
    fputs("                          when creating a seed.\n", stderr);
    fputs("\n", stderr);
    fputs("examples:\n", stderr);
    fputs("\n", stderr);
    fputs("  Create a random seed of 16 bytes eg. 128 bits seed and generate mnemonics\n", stderr);
    fputs("\n", stderr);
    fputs("      head -c16 /dev/random | btct bip39 --mnemonics\n", stderr);
    fputs("\n", stderr);
    fputs("  Testing using test vector\n", stderr);
    fputs("\n", stderr);
    fputs("      echo '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f' | xxd -r -p | btct bip39.mnemonics\n", stderr);
    fputs("\n", stderr);

}

static int
_bip39_mnemonics_command(int argc, char **argv)
{
    int c;
    _mnemonics_format_t format = PRETTY;

    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {"sentence",  no_argument, 0, 's' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hs", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                _bip39_mnemonics_command_usage();
                return EXIT_FAILURE;

            case 's':
                format = SENTENCE;
                break;
        }
    }

    return _bip39_to_mnemonics(format);
}


static int _bip39_to_seed(int iterations, const char *passphrase)
{
    uint8_t seed[64]={0};
    uint8_t mnemonics[4096]={0};
    size_t bytes = 0;

    freopen(NULL, "rb", stdin);
    while (fread(mnemonics + bytes, 1, 1, stdin))
        bytes++;

    // strip newline
    if (mnemonics[bytes-1] == '\n') {
        mnemonics[bytes-1] = '\0';
        bytes--;
    }

    bip39_t ctx;
    if (bip39_init(&ctx) != 0) {
        fprintf(stderr, "bip39.seed: failed to initialize bip39 context\n");
        return EXIT_FAILURE;
    }

    if (bip39_to_seed(&ctx, mnemonics, bytes, iterations, (uint8_t*)passphrase, seed) != 0) {
        fprintf(stderr, "bip39.seed: failed to generate seed from mnenomics\n");
        return EXIT_FAILURE;
    }

    freopen(NULL, "wb", stdout);
    fwrite(seed, 1, 64, stdout);
    fflush(stdout);
    
    return EXIT_SUCCESS;
}

static void
_bip39_seed_command_usage()
{
    fputs("usage: btct bip39.seed <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  -i, --iterations <count>  Override the default iterations of 2048 for PBKDF2 routine\n", stderr);
    fputs("  -p, --passphrase          Passphrase for generating 'hidden' wallet\n", stderr);
    fputs("\n", stderr);
    fputs("  Generate seed with passphrase\n", stderr);
    fputs("\n", stderr);
    fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' \\\n",stderr);
    fputs("          | btct bip39.seed --passphrase=TREZOR\n", stderr);
    fputs("\n", stderr);
}

static  int
_bip39_seed_command(int argc, char **argv)
{
    int c;

    const char *passphrase=NULL;
    int iterations = 2048;
    
    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {"passphrase",  required_argument, 0, 'p' },
            {"iterations",  required_argument, 0, 'i' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hp:i:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                _bip39_seed_command_usage();
                return EXIT_FAILURE;

            case 'p':
                passphrase = optarg;
                break;

            case 'i':
                iterations = atoi(optarg);
                break;
        }
    }

    return _bip39_to_seed(iterations, passphrase);
}

static void _bip39_command_usage()
{
    fputs("usage: btct bip39.<command> <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  mnemonics       Generate mnemonics sentence from specified entrophy read from\n", stderr);
    fputs("                  stdin, writing mnemonic words to stdout.\n", stderr);
    fputs("  seed            Generates seed from sentence read from stdin\n", stderr);
    fputs("\n",stderr);
    fputs("examples:\n", stderr);
    fputs("\n",stderr);
    fputs("  Generate bip39 seed from hex string entropy using a passphrase:\n",stderr);
    fputs("\n",stderr);
    fputs("      echo '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f' | \\\n", stderr);
    fputs("        xxd -r -p | btct bip39.mnemonics --sentence | \\\n", stderr);
    fputs("        btct bip39.seed --passphrase=TREZOR | hexdump -C\n", stderr);
    fputs("\n", stderr);
}

int bip39_command(int argc, char **argv)
{
    int res;

    struct command_t commands[] = {
        { "bip39.seed", _bip39_seed_command },
        { "bip39.mnemonics", _bip39_mnemonics_command },
        { NULL, NULL, }
    };

    res = command_dispatch(commands, argv[0], false, argc, argv);
    if (res == -1)
        _bip39_command_usage();

    return (res != EXIT_SUCCESS ? EXIT_FAILURE : EXIT_SUCCESS);
}
