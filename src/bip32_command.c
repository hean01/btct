#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>

#include "command.h"
#include "bip32.h"
#include "utils.h"

static int
_bip32_masterkey(bool encode, bool wif)
{
    uint8_t seed[128]={0};
    size_t bytes = 0;

    // Read entrophy bits from stdin
    freopen(NULL, "rb", stdin);
    while (fread(seed + bytes, 1, 1, stdin))
        bytes++;

    fprintf(stderr,"bip39.masterkey: read %ld bits of seed from stdin to use for creating hierarchical deterministic master key\n", bytes*8);

    char buffer[4096];
    size_t size = sizeof(buffer);

    bip32_key_t ctx;
    bip32_key_init_from_entropy(&ctx, seed, bytes);

    freopen(NULL, "wb", stdout);
    if (!wif)
    {
        bip32_key_serialize(&ctx, encode, (uint8_t*)buffer, &size);
        fwrite(buffer, 1, size, stdout);
        if (encode)
            fputs("\n", stdout);
    }
    else
    {
        bip32_key_to_wif(&ctx, (uint8_t*)buffer, &size);
        fwrite(buffer, 1, size, stdout);
    }

    return EXIT_SUCCESS;
}

static void
_bip32_masterkey_usage(void)
{
    fputs("usage: btct bip32.masterkey <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  -p, --plain          Do not perform base58 encoding of key\n", stderr);
    fputs("  -w, --wif            Wallet import format\n", stderr);
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
_bip32_masterkey_command(int argc, char **argv)
{
    int c;
    bool encode = true;
    bool wif = false;
    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {"plain",  no_argument, 0, 'p' },
            {"wif",  no_argument, 0, 'w' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hpw", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                _bip32_masterkey_usage();
                return EXIT_FAILURE;

            case 'p':
                encode = false;
                break;

            case 'w':
                wif = true;
                break;
        }
    }

    return _bip32_masterkey(encode, wif);
}

static int
_bip32_derive_key(const char *path)
{
    bip32_key_t key, child;
    char encoded_key[4096]={0};
    uint8_t buf[512] = {0};
    size_t bytes = 0;

    freopen(NULL, "rb", stdin);
    while (fread( encoded_key + bytes, 1, 1, stdin))
        bytes++;

    // strip newline
    if (encoded_key[bytes-1] == '\n') {
        encoded_key[bytes-1] = '\0';
        bytes--;
    }

    if (bip32_key_deserialize(&key, encoded_key) != 0)
    {
      fputs("bip32.derive: Failed to deserialize key from stdin\n", stderr);
      return -1;
    }

    fprintf(stderr,"bip32.derive: Deriving key from path: %s\n", path);
    if (bip32_key_derive_child_by_path(&key, path, &child) != 0)
      return -2;

    bytes = sizeof(buf);
    bip32_key_serialize(&child, true, buf, &bytes);

    fprintf(stdout, "%s\n", buf);
    return 0;
}

static void
_bip32_derive_usage(void)
{
    fputs("usage: btct bip32.derive <args>\n", stderr);
    fputs("\n", stderr);
    fputs("", stderr);
    fputs("\n", stderr);
    fputs("  -p, --path          Specify a derivation path, default path if not specified is\n", stderr);
    fputs("                      following hardened årivate key for wallet account 0: `m/0'/0`.\n", stderr);
    fputs("\n", stderr);
    fputs("examples:\n", stderr);
    fputs("\n", stderr);
    fputs("  Create a HD wallet master key from mnemonics and derive a hardened wallet key for account #1:\n", stderr);
    fputs("\n", stderr);
    fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' | \\\n", stderr);
    fputs("        btct bip39.seed --passphrase=TREZOR | \\\n", stderr);
    fputs("        btct bip32.masterkey | \\\n", stderr);
    fputs("        btct bip32.derive --path=\"m/0'/1\"\\\n", stderr);
    fputs("\n", stderr);
}

static int
_bip32_derive_command(int argc, char **argv) {
    int c;
    const char *path;
    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {"path",  required_argument, 0, 'p' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hp", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                _bip32_derive_usage();
                return EXIT_FAILURE;

            case 'p':
                path = optarg;
                break;
        }
    }

    return _bip32_derive_key(path);
}

static int
_bip32_pubkey()
{
    bip32_key_t key, public;
    char encoded_key[4096]={0};
    uint8_t buf[512] = {0};
    size_t bytes = 0;

    freopen(NULL, "rb", stdin);
    while (fread( encoded_key + bytes, 1, 1, stdin))
        bytes++;

    // strip newline
    if (encoded_key[bytes-1] == '\n') {
        encoded_key[bytes-1] = '\0';
        bytes--;
    }

    if (bip32_key_deserialize(&key, encoded_key) != 0)
    {
      fputs("bip32.pubkey: Failed to deserialize key from stdin\n", stderr);
      return -1;
    }

    if (key.public == true)
    {
      fputs("bip32.pubkey: Failed, not a private key\n", stderr);
      return -2;
    }

    if (bip32_key_init_public_from_private_key(&public, &key) != 0)
      return -3;

    bytes = sizeof(buf);
    bip32_key_serialize(&public, true, buf, &bytes);

    fprintf(stdout, "%s\n", buf);
    return 0;
}

static void
_bip32_pubkey_usage(void)
{
    fputs("usage: btct bip32.pubkey\n", stderr);
    fputs("\n", stderr);
    fputs("Reads a encoded private key and outputs its corresponding public key in encoded format.\n", stderr);
    fputs("\n", stderr);
    fputs("examples:\n", stderr);
    fputs("\n", stderr);
    fputs("  Create a HD wallet master key from mnemonics and print its public key:\n", stderr);
    fputs("\n", stderr);
    fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' | \\\n", stderr);
    fputs("        btct bip39.seed --passphrase=TREZOR | \\\n", stderr);
    fputs("        btct bip32.masterkey | \\\n", stderr);
    fputs("        btct bip32.pubkey\n", stderr);
    fputs("\n", stderr);
}

static int
_bip32_pubkey_command(int argc, char **argv)
{
    int c;
    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hp", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                _bip32_pubkey_usage();
                return EXIT_FAILURE;
        }
    }

    return _bip32_pubkey();
}

static int
_bip32_describe(bool show_private)
{
    bip32_key_t *pkey, public_key, key;
    bip32_key_identifier_t identifier;
    uint8_t fingerprint[4] = {0};
    char encoded_key[4096]={0};
    uint8_t buf[512] = {0};
    size_t bytes = 0;

    freopen(NULL, "rb", stdin);
    while (fread( encoded_key + bytes, 1, 1, stdin))
        bytes++;

    // strip newline
    if (encoded_key[bytes-1] == '\n') {
        encoded_key[bytes-1] = '\0';
        bytes--;
    }

    if (bip32_key_deserialize(&key, encoded_key) != 0)
    {
      fputs("bip32.describe: failed to deserialize key from stdin\n", stderr);
      return EXIT_FAILURE;
    }
    pkey = &key;

    if (!show_private && !pkey->public) {
      if (bip32_key_init_public_from_private_key(&public_key, &key) != 0)
        return EXIT_FAILURE;
      pkey = &public_key;

      bytes = sizeof(encoded_key);
      if (bip32_key_serialize(pkey, true, (uint8_t *)encoded_key, &bytes) != 0)
        return EXIT_FAILURE;
    }

    bip32_key_identifier_init_from_key(identifier, pkey);
    bip32_key_identifier_fingerprint(identifier, fingerprint);

    fputs( pkey->public ? "\n" : "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n", stdout);
    fprintf(stdout, "  %s\n" , encoded_key);
    fputs( pkey->public ? "\n" : "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n", stdout);

    fprintf(stdout, "         Fingerprint: %.2x%.2x%.2x%.2x\n",
            fingerprint[0], fingerprint[1],
            fingerprint[2], fingerprint[3]);

    if (pkey->public) {
      uint8_t serialized_public_key[33]={0};
      if (bip32_key_secp256k1_serialize_public_key(pkey, true, serialized_public_key) != 0)
        return -2;
      utils_to_hex_string(serialized_public_key, sizeof(serialized_public_key), (char*)buf);
    } else {
      bytes = sizeof(buf);
      if (bip32_key_to_wif(pkey, buf, &bytes) != 0)
        return -3;
    }
    fprintf(stdout, "%20s: %s\n", pkey->public ? "Key" : "Key (WIF)", buf);

    bytes = sizeof(buf);
    bip32_key_p2pkh_address_from_key(pkey, buf, &bytes);
    fprintf(stdout, "     Address (P2PKH): %s\n", buf);

    fprintf(stdout, "  Parent fingerprint: %.2x%.2x%.2x%.2x\n",
            key.parent_fingerprint[0], key.parent_fingerprint[1],
            key.parent_fingerprint[2], key.parent_fingerprint[3]);

    fputs("\n", stdout);
    return EXIT_SUCCESS;
}

static void
_bip32_describe_usage(void)
{
    fputs("usage: btct bip32.describe\n", stderr);
    fputs("\n", stderr);
    fputs("Deserialize an extended key and prints out detailes about the the key, this will reveal\n", stderr);
    fputs("sensitive data as extended private key.\n", stderr);
    fputs("\n", stderr);
    fputs("  -p, --private       Describe the a private extended key, default behaviour is to derive\n",stderr);
    fputs("                      the public extended key and describe to prevent to disclose private\n", stderr);
    fputs("                      data to the console.\n", stderr);
    fputs("\n", stderr);
    fputs("examples:\n", stderr);
    fputs("\n", stderr);
    fputs("  Create a HD wallet master key from mnemonics and describe private details to console:\n", stderr);
    fputs("\n", stderr);
    fputs("      echo 'legal winner thank year wave sausage worth useful legal winner thank yellow' | \\\n", stderr);
    fputs("        btct bip39.seed --passphrase=TREZOR | \\\n", stderr);
    fputs("        btct bip32.masterkey | \\\n", stderr);
    fputs("        btct bip32.describe --private\n", stderr);
    fputs("\n", stderr);
}

static int
_bip32_describe_command(int argc, char **argv) {
    int c;
    bool show_private = false;
    while (1)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",  no_argument, 0, 'h' },
            {"private",  no_argument, 0, 'p' },
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hp", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                _bip32_describe_usage();
                return EXIT_FAILURE;
            case 'p':
                show_private = true;
        }
    }

    return _bip32_describe(show_private);
}

static void _bip32_command_usage(void)
{
    fputs("usage: btct bip32.<command> <args>\n", stderr);
    fputs("\n", stderr);
    fputs("  masterkey        Generate hierarchical deterministic master key\n", stderr);
    fputs("  pubkey           Generate public key for private key in encoded format\n", stderr);
    fputs("                   read from stdin.\n", stderr);
    fputs("  derive           Derive a key from specified derivation path\n", stderr);
    fputs("  describe         Deserialize an extended key and prints information\n", stderr);
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
        { "bip32.masterkey", _bip32_masterkey_command },
        { "bip32.pubkey", _bip32_pubkey_command },
        { "bip32.derive", _bip32_derive_command },
        { "bip32.describe", _bip32_describe_command },
        { NULL, NULL, }
    };

    res = command_dispatch(commands, argv[0], false, argc, argv);
    if (res == -1)
        _bip32_command_usage();

    return (res != EXIT_SUCCESS ? EXIT_FAILURE : EXIT_SUCCESS);
}
