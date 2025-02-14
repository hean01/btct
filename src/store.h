#ifndef __store_h__
#define __store_h__

int store_write_mnemonics(const char *filename, const char *password, const uint8_t *mnemonics);
int store_read_mnemonics(const char *filename, const char *password,
                         uint8_t *data, size_t *size);

#endif
