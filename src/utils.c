#include <ctype.h>
#include <fcntl.h>
#include "utils.h"

void
utils_hexdump(uint8_t *data, size_t size, FILE *out) {
    size_t rows =  1 + size / 16;
    size_t byte_offset = 0;

    fprintf(out, "Hexdump of %ld bytes of data:\n", size);
    
    for (size_t row = 0; row < rows; row++) {
        byte_offset = row * 16;
        fprintf(out, "%8.8lx ", byte_offset);

        uint8_t byte;
        char str[17] = { 0 };
        for (byte = 0; byte < 16; byte++) {
            if ((byte_offset + byte) == size)
                break;

            str[byte] = isprint(data[byte_offset + byte]) != 0 ? data[byte_offset + byte] : '.';
            fprintf(out, " %.2x", data[byte_offset + byte]);
        }
        fprintf(out,  "  |%s|\n", str);
        if (byte_offset + byte == size)
            break;
    }
    fprintf(out, "%8.8lx\n", byte_offset + 16);
}

int
utils_to_hex_string(const uint8_t *data, size_t size, char *result)
{
  char buf[16];
  result[0] = '\0';
  for (size_t i = 0; i < size; i++) {
    sprintf(buf, "%.2x", data[i]);
    strcat(result, buf);
  }
  return 0;
}

int
utils_base85_encode(const uint8_t *data, size_t size, char *result)
{
  // Using rfc1925 variant
  static char *base85="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

  uint32_t value;
  uint8_t *pdata = data;
  uint8_t *presult = result;

  while (1) {
    if (pdata >= data + size)
      break;

    value = utils_in_u32_be(pdata);

    if (value == 0) {
      *presult = 'z';
      pdata += 4;
      continue;
    }

    uint32_t b1 = value % 85;
    value = (value - b1) / 85;
    uint32_t b2 = value % 85;
    value = (value - b2) / 85;
    uint32_t b3 = value % 85;
    value = (value - b3) / 85;
    uint32_t b4 = value % 85;
    value = (value - b4) / 85;
    uint32_t b5 = value % 85;

    presult[0] = base85[b5];
    presult[1] = base85[b4];
    presult[2] = base85[b3];
    presult[3] = base85[b2];
    presult[4] = base85[b1];
    presult += 5;

    pdata += 4;
  }

  return 0;
}

int
utils_fill_random(uint8_t *out, size_t size)
{
  int h = open("/dev/urandom", O_RDONLY);
  if (read(h, out, size) < size)
    return -1;
  close(h);
  return 0;
}
