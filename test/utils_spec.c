#include "./bdd-for-c.h"
#include "../src/utils.h"

#define check_str(got, expected) check(strcmp(got, expected) == 0, "expected string '%s' got '%s'", expected, got)
#define check_number(got, expected) check(got == expected, "expected '%u' got '%u'", expected, got)
#define check_number_hex(got, expected) check(got == expected, "expected '0x%x' got '0x%x'", expected, got)

spec("bip32") {
  uint16_t u16 = 0xff01;
  uint32_t u32 = 0xfffe0102;

  context("in/out of big endian values") {

    describe("when writing u16 big endian") {
      uint8_t buf[16];
      uint8_t expected[] = { 0xff, 0x01 };
      utils_out_u16_be(buf, u16);
      it("should write expected value")
	check(memcmp(buf, expected, 2) == 0);
    }

    describe("when reading u16 big endian") {
      uint8_t buf[] = { 0xff, 0x01 };
      uint16_t value = utils_in_u16_be(buf);
      it("should write expected value")
	check_number_hex(value, u16);
    }

    describe("when writing u32 big endian") {
      uint8_t buf[16];
      uint8_t expected[] = { 0xff, 0xfe, 0x01, 0x02 };
      utils_out_u32_be(buf, u32);
      it("should write expected value")
	check(memcmp(buf, expected, 2) == 0);
    }

    describe("when reading u32 big endian") {
      uint8_t buf[] = { 0xff, 0xfe, 0x01, 0x02 };
      uint32_t value = utils_in_u32_be(buf);
      it("should write expected value")
	check_number_hex(value, u32);
    }
  }

  context("base85 encoding") {
    describe("when encoding 0x000000") {
      static uint8_t data[] = {0x00, 0x00, 0x00, 0x00};
      static char result[512] = {0};
      before() {
        utils_base85_encode(data, 4, result);
      }
      it("should return 'z'")
        check_str(result, "z");
    }

    describe("when encoding 'helloyou'") {
      static uint8_t data[] = {'h', 'e', 'l', 'l', 'o', 'y', 'o', 'u'};
      static char result[512] = {0};
      before() {
        utils_base85_encode(data, 8, result);
      }
      it("should return 'Xk~0{Z+UNZ'")
        check_str(result, "Xk~0{Z+UNZ");
    }
  }
}
