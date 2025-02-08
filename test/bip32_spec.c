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

  context("Given initialized key from know seed") {
    before_each() {
      bip32_key_init_from_entropy(&key, vectors[0].seed, sizeof(vectors[0].seed));
    }


    describe("when serializing bip32 root key") {
      char buffer[1024];
      size_t size = sizeof(buffer);
      bip32_key_serialize(&key, true, (uint8_t*)buffer, &size);
      it("should return the correct xprv* string")
	check_str(buffer, vectors[0].masterkey);

      describe("and deserialize result") {
        bip32_key_t deserialized_key;
        int result = bip32_key_deserialize(&deserialized_key, buffer);
        it ("should create same key")
          check(memcmp(&key, &deserialized_key, sizeof(bip32_key_t)) == 0);
      }
    }

    describe("when deserializing bip32 root key") {
      bip32_key_t deserialized_key;
      int result = bip32_key_deserialize(&deserialized_key, vectors[0].masterkey);
      it("should not fail deserialize")
        check_number(result, 0);

      it("should deserialize to a private key")
        check(deserialized_key.public == false);
    }
  }
}
