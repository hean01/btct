#ifndef __store_h__
#define __store_h__

int store_write_seed(const char *filename, const char *password, const uint8_t *mnemonincs, size_t size);
int store_read_seed(const char *filename, const char *password,
                         uint8_t *mnemonincs, size_t size);

#endif
