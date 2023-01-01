#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include "command.h"

extern int (bip32_command)(int,char**);
extern int (bip39_command)(int,char**);

static command_t commands[] = {
    { "bip32", bip32_command },
    { "bip39", bip39_command },
    { NULL, NULL, }
};

static void usage()
{
    fputs("usage: btct [-v | --version] [-h | --help]\n", stderr);
    fputs("               <module>.<command> [<args>]\n", stderr);
    fputs("\n", stderr);
    fputs("These are the BiTCoin Tools (btct) modules used in various situations:\n", stderr);
    fputs("\n", stderr);
    fputs("  bip32        Hierarchical Deterministic Wallets\n", stderr);
    fputs("  bip39        Mnemonic code for generating deterministic keys\n", stderr);
    fputs("\n", stderr);
}

static void version()
{
    fputs("bct v1.0.0\n", stderr);
}

int
main(int argc, char **argv)
{

    int i, c;
    char *command;
    int argc_command = argc;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-')
            continue;

        command = argv[i];
        argv[i] = NULL;
        argc_command = i;
        break;
    }
    
    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {"version", no_argument, 0, 'v'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc_command, argv, "hv", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage();
                return EXIT_FAILURE;
            case 'v':
                version();
                return EXIT_FAILURE;
        }
    }

    if (optind == argc)
    {
        usage();
        exit(EXIT_FAILURE);
    }

    argc = argc - argc_command;
    argv += argc_command;
    *argv = command;

    int res = command_dispatch(commands, command, true, argc, argv);
    if (res == -1)
        usage();

    exit(res != EXIT_SUCCESS ? EXIT_FAILURE : EXIT_SUCCESS);
}
