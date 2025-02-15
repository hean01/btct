#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <nettle/aes.h>
#include <nettle/pbkdf2.h>

#include "bip39_english.h"

#include "store.h"
#include "utils.h"

#define KEY_SIZE 32

static int
_derive_key(const char *password, uint8_t *key) {
  static size_t iterations = 4096;
  static char *salt = "btct_store_password";
  pbkdf2_hmac_sha512(strlen(password), password, iterations, strlen(salt), salt, KEY_SIZE, key);

  return 0;
}

static uint16_t
_lookup_mnemonic_index(const char *mnemonic)
{
  char *pend = mnemonic;
  while (*pend != ' ' && *pend != '\0' && *pend != '\n')
    pend++;

  for (size_t i = 0; i < 2047; i++) {
    if (strncmp(bip39_english[i], mnemonic, pend - mnemonic) == 0)
      return i;
  }
  return 0xffff;
}

static int
_mnemonics_to_data(const char *mnemonics, uint8_t *out)
{
  uint16_t cnt = 0;
  uint8_t *pout = out;
  char *ps = mnemonics;

  while (1) {
    uint16_t idx =  _lookup_mnemonic_index(ps);
    utils_out_u16_be(pout, idx);
    if ( pout[0] == 0xff && pout[1] == 0xff)
      return -1;

    cnt++;

    // advance to start of next word
    while(*ps != ' ' && *ps != '\0')
      ps++;

    if (*ps == '\0')
      break;

    ps++;
    pout+=2;
  }

  return cnt;
}

int
_write_store_file(const char *filename, const uint8_t *data, size_t size)
{
  char file[2048] = {0};
  char *home_dir = getenv("HOME");
  if (filename == NULL)
    snprintf(file, sizeof(file),  "%s/.btct.dat", home_dir != NULL ? home_dir : "./" );
  else
    realpath(file, filename);

  int out = open(file, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);
  if (out == -1) {
    perror("open failed with reason");
    return -1;
  }

  write(out, data, size);
  close(out);

  return 0;
}

int
_read_store_file(const char *filename, uint8_t *data, size_t size) {
  char file[2048] = {0};
  char *home_dir = getenv("HOME");
  if (filename == NULL)
    snprintf(file, sizeof(file),  "%s/.btct.dat", home_dir != NULL ? home_dir : "./" );
  else
    realpath(file, filename);

  int out = open(file, O_RDONLY);
  if (out == -1) {
    perror("open failed with reason");
    return -1;
  }

  read(out, data, size);
  close(out);

  return 0;
}

int
store_write_mnemonics(const char *filename, const char *password, const uint8_t *mnemonics)
{
  uint8_t block[128] = {0};
  uint8_t data[128] = {0};
  int res;
  uint8_t key[KEY_SIZE];
  struct aes_ctx aes;

  // derive key from password
  _derive_key(password, &key);

  // fill block with random data
  if (utils_fill_random(block, sizeof(block)) != 0)
    return -1;

  // write mnemonics indicies to block
  res = _mnemonics_to_data(mnemonics, block);
  if (res == -1)
    return -2;

  // add marker for end of mnemonics
  block[res*2] = 0xff;
  block[1 + res*2] = 0xff;

  // encrypt block
  aes_set_encrypt_key(&aes, KEY_SIZE, key);
  aes_encrypt(&aes, sizeof(block), data, (uint8_t*)block);

  // write to file
  _write_store_file(filename, data, sizeof(data));
  return 0;
}

int store_read_mnemonics(const char *filename, const char *password,
                         uint8_t *data, size_t *size)
{
  uint8_t block[128];
  uint8_t decrypted_block[128];
  uint8_t key[KEY_SIZE];
  struct aes_ctx aes;

  // derive key from password
  _derive_key(password, &key);

  // read file from store
  if (_read_store_file(filename, block, sizeof(block)) != 0)
    return -1;

  // decrypt using aes
  aes_set_decrypt_key(&aes, KEY_SIZE, key);
  aes_decrypt(&aes, sizeof(block), decrypted_block, block);

  // create mnemonics from data
  uint8_t *pdata = decrypted_block;
  uint8_t cnt = 1;

  while(cnt <= 24) {
    uint16_t idx =  utils_in_u16_be(pdata);
    if (idx == 0xffff)
      break;
    else if(pdata != decrypted_block)
      fputs(" ", stdout);

    idx = idx & 0x07ff;

    fputs(bip39_english[idx], stdout);

    pdata += 2;
    cnt++;
  }

  return 0;
}
