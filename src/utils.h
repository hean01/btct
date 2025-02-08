#ifndef __utils_h
#define __utils_h
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef LITTLE_ENDIAN
#define utils_out_u16_be(p, v) \
  {                                                     \
    *(p + 1) = (v) & 0xff;                              \
    *(p + 0) = ((v) >> 8) & 0xff;                       \
  }
#define utils_out_u32_be(p, v) \
  {                                                                     \
    utils_out_u16_be(p + 2, (v) & 0xffff);                              \
    utils_out_u16_be(p + 0, ((v) >> 16) & 0xffff);                      \
  }
#define utils_in_u16_be(p) ((uint16_t) *(p + 0) << 8 | *(p + 1))
#define utils_in_u32_be(p) ((uint32_t) utils_in_u16_be(p + 0) << 16 | utils_in_u16_be(p + 2))

#else /* big endian */
#define utils_out_u16_be(p, v)                  \
  {                                             \
    *(p + 0) = (v) & 0xff;                      \
    *(p + 1) = ((v) >> 8) & 0xff;               \
  }
#define utils_out_u32_be(p, v) \
  {                                                                     \
    utils_out_u16_be(p + 0, (v) & 0xffff);                              \
    utils_out_u16_be(p + 2, ((v) >> 16) & 0xffff);                          \
  }
#define utils_in_u16_be(p) ((uint16_t) *(p + 0) << 8 | *(p + 1))
#define utils_in_u32_be(p) ((uint32_t) utils_in_u16_be(p) << 16 | utils_in_u16_be(p + 2))
#endif

void utils_hexdump(uint8_t *data, size_t size, FILE *out);

#endif
