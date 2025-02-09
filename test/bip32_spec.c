#include "./bdd-for-c.h"
#include "./test_vectors.h"
#include "../src/bip32.h"

#define check_str(got, expected) check(strcmp(got, expected) == 0, "expected string '%s' got '%s'", expected, got)
#define check_number(got, expected) check(got == expected, "expected '%d' got '%d'", expected, got)

spec("bip32") {

  context("given initializing key from entropy") {
    static bip32_key_t key;

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

  context("given initialized master key from know seed") {
    static bip32_key_t key;
    static bip32_key_t public_key;
    static int result = -1;

    before_each() {
      result = bip32_key_init_from_entropy(&key, vectors[0].seed, sizeof(vectors[0].seed));
    }

    it("should not return error")
      check_number(result, 0);

    describe("when serializing master key") {
      char buffer[1024];
      static size_t size = sizeof(buffer);
      static int result = -1;

      before_each() {
        result = bip32_key_serialize(&key, true, (uint8_t*)buffer, &size);
      }

      it("then should not return error")
        check_number(result, 0);

      it("then should return the correct xprv* string")
	check_str(buffer, vectors[0].masterkey);
    }

    describe("when deserializing master key") {
      static bip32_key_t deserialized_key;
      static int result = -1;
      before() {
        result = bip32_key_deserialize(&deserialized_key, vectors[0].masterkey);
      }
      it("then should not return error")
        check_number(result, 0);

      it ("then should create expected key")
          check(memcmp(&key, &deserialized_key, sizeof(bip32_key_t)) == 0);
    }

    context("and generating public key") {
      static int result = -1;
      before() {
        result = bip32_key_init_public_from_private_key(&public_key, &key);
      }

      it("should not fail")
        check_number(result, 0);

      describe("when serialize of public key") {
        char buffer[1024];
        static size_t size = sizeof(buffer);
        static int result = -1;

        before_each() {
          result = bip32_key_serialize(&public_key, true, (uint8_t*)buffer, &size);
        }

        it("then should not return error")
          check_number(result, 0);

        it("should return the expected xpub* string")
          check_str(buffer, vectors[0].publickey);
      }
    }

    describe("when deserializing known public key") {
      static bip32_key_t deserialized_key;
      static int result = -1;

      before() {
        bip32_key_init_public_from_private_key(&public_key, &key);
        result = bip32_key_deserialize(&deserialized_key, vectors[0].publickey);
      }

      it("then should not fail deserialize")
        check_number(result, 0);

      it ("then should create expected key")
          check(memcmp(&public_key, &deserialized_key, sizeof(bip32_key_t)) == 0);
    }
  }
}
