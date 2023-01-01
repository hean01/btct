#include <ctype.h>
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
