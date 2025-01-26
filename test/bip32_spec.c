#include "./bdd-for-c.h"
#include "./test_vectors.h"
#include "../src/bip32.h"

#define check_str(got, expected) check(strcmp(got, expected) == 0, "expected string '%s' got '%s'", expected, got)
#define check_number(got, expected) check(got == expected, "expected '%d' got '%d'", expected, got)

spec("bip32") {
  static bip32_key_t key;

  context("given initializing key from entropy") {
    before_each() {
    }

    describe("when using 32bit entropy") {
      static uint8_t entropy[] = {0,0,0,0};
      it("then it should fail")
	check(bip32_key_init_from_entropy(&key, entropy, sizeof(entropy)) != 0);
    }

    describe("when using 128bit entropy") {
      static uint8_t entropy[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
      it("then it should fail")
	check(bip32_key_init_from_entropy(&key, entropy, sizeof(entropy)) != 0);
    }

    describe("when using 256bit entropy") {
      static uint8_t entropy[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
      it("then it should fail")
	check(bip32_key_init_from_entropy(&key, entropy, sizeof(entropy)) != 0);
    }

    describe("when using required 512bit entropy") {
      static uint8_t entropy[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
      it("then it should succeed")
	check(bip32_key_init_from_entropy(&key, entropy, sizeof(entropy)) == 0);
    }
  }
}
