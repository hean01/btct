#include <stdint.h>
typedef struct test_vector_t {
  uint8_t entropy[32];
  uint8_t entropy_bytes;
  char *mnemonics[24];
  uint8_t privkey[64];
  char *masterkey;
} test_vector_t;

static test_vector_t vectors[] = {
  {
    .entropy = { 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f },
    .entropy_bytes = 16,
    .mnemonics = { "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "yellow" },
    .privkey = {
      0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05, 0xed,
      0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e, 0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34, 0x95, 0x53,
      0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82, 0x64, 0xc1, 0xe1, 0xc9, 0x2f, 0x2c, 0xf1, 0x41,
      0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b, 0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04
    },
    .masterkey = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
  },

  {
    .entropy = {
      0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
      0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    },
    .entropy_bytes = 24,
    .mnemonics = {
      "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank",
      "year", "wave", "sausage", "worth", "useful", "legal", "will"
    },
    .privkey = {
      0xf2, 0xb9, 0x45, 0x08, 0x73, 0x2b, 0xcb, 0xac, 0xbc, 0xc0, 0x20, 0xfa, 0xef, 0xec, 0xfc, 0x89,
      0xfe, 0xaf, 0xa6, 0x64, 0x9a, 0x54, 0x91, 0xb8, 0xc9, 0x52, 0xce, 0xde, 0x49, 0x6c, 0x21, 0x4a,
      0x0c, 0x7b, 0x3c, 0x39, 0x2d, 0x16, 0x87, 0x48, 0xf2, 0xd4, 0xa6, 0x12, 0xba, 0xda, 0x07, 0x53,
      0xb5, 0x2a, 0x1c, 0x7a, 0xc5, 0x3c, 0x1e, 0x93, 0xab, 0xd5, 0xc6, 0x32, 0x0b, 0x9e, 0x95, 0xdd,
    },
    .masterkey = "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VT4gz4wt5RM23pkaQLnvBh7",
  },

  {
    .entropy = {
      0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
      0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
    },
    .entropy_bytes = 32,
    .mnemonics = {
      "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "year",
      "wave", "sausage", "worth", "useful", "legal", "winner", "thank", "year", "wave", "sausage", "worth", "title"
    },
    .privkey = {
      
      0xbc, 0x09, 0xfc, 0xa1, 0x80, 0x4f, 0x7e, 0x69, 0xda, 0x93, 0xc2, 0xf2, 0x02, 0x8e, 0xb2, 0x38,
      0xc2, 0x27, 0xf2, 0xe9, 0xdd, 0xa3, 0x0c, 0xd6, 0x36, 0x99, 0x23, 0x25, 0x78, 0x48, 0x0a, 0x40,
      0x21, 0xb1, 0x46, 0xad, 0x71, 0x7f, 0xbb, 0x7e, 0x45, 0x1c, 0xe9, 0xeb, 0x83, 0x5f, 0x43, 0x62,
      0x0b, 0xf5, 0xc5, 0x14, 0xdb, 0x0f, 0x8a, 0xdd, 0x49, 0xf5, 0xd1, 0x21, 0x44, 0x9d, 0x3e, 0x87,
    },
    .masterkey = "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU"
  }
};
