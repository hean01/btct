#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <nettle/aes.h>
#include <nettle/pbkdf2.h>

#include "store.h"

#define KEY_SIZE 32

static int
_derive_key(const char *password, uint8_t *key) {
  static size_t iterations = 4096;
  static char *salt = "btct_store_password";
  pbkdf2_hmac_sha512(strlen(password), password, iterations, strlen(salt), salt, KEY_SIZE, key);

  return 0;
}


int
store_write_seed(const char *filename, const char *password, const uint8_t *seed, size_t size)
{
  uint8_t data[4096] = {0};
  char buf[4096] = {0};
  uint8_t key[KEY_SIZE];
  struct aes_ctx aes;

  // derive key from password
  _derive_key(password, &key);

  // encrypt using aes
  memcpy(buf, seed, size);
  aes_set_encrypt_key(&aes, KEY_SIZE, key);
  aes_encrypt(&aes, size, data, buf);

  // write to store
  char *home_dir = getenv("HOME");
  if (filename == NULL)
    snprintf(buf, sizeof(buf),  "%s/.btct.dat", home_dir != NULL ? home_dir : "./" );
  else
    realpath(buf, filename);

  int out = open(buf, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU);
  if (out == -1) {
    perror("open failed with reason");
    return -1;
  }

  write(out, data, size);
  close(out);

  return 0;
}

int store_read_seed(const char *filename, const char *password,
                    uint8_t *seed, size_t size)
{
  uint8_t data[4096];
  char file[4096] = {0};
  size_t bytes;
  uint8_t key[KEY_SIZE];
  struct aes_ctx aes;

  // derive key from password
  _derive_key(password, &key);

  // read store
  char *home_dir = getenv("HOME");
  if (filename == NULL)
    snprintf(file, sizeof(file),  "%s/.btct.dat", home_dir != NULL ? home_dir : "./" );
  else
    realpath(file, filename);

  int in = open(file, O_RDONLY);
  if (in == -1) {
    perror("open failed with reason");
    return -1;
  }

  bytes = read(in, data, 4096);
  close(in);

  if (bytes == -1)
    return -2;

  // decrypt using aes
  aes_set_decrypt_key(&aes, KEY_SIZE, key);
  aes_decrypt(&aes, bytes, seed, data);

  return 0;
}
