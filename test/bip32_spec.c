#include "./bdd-for-c.h"
#include "./test_vectors.h"
#include "../src/bip32.h"

#define check_str(got, expected) check(strcmp(got, expected) == 0, "expected string '%s' got '%s'", expected, got)
#define check_number(got, expected) check(got == expected, "expected '%d' got '%d'", expected, got)
#define check_number_hex(got, expected) check(got == expected, "expected '0x%x' got '0x%x'", expected, got)
//#define check_bytes(got, expected, size) check(memcmp(got, expected, size) == 0, "expected '0x%x' got '0x%x'", expected, got)

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

    context("and generating public key") {
      static int result = -1;
      before() {
        result = bip32_key_init_public_from_private_key(&public_key, &key);
      }

      it("should not fail")
        check_number(result, 0);
    }
  }

  context("key (de)serialization") {
    static bip32_key_t private_key;
    static bip32_key_t public_key;
    static int result = -1;

    before() {
      bip32_key_init_from_entropy(&private_key, vectors[0].seed, sizeof(vectors[0].seed));
      bip32_key_init_public_from_private_key(&public_key, &private_key);
    }

    describe("when serializing master key (m)") {
      uint8_t buffer[1024];
      static size_t size = sizeof(buffer);
      static int result = -1;

      before_each() {
        result = bip32_key_serialize(&private_key, false, (uint8_t*)buffer, &size);
      }

      it("then not return error")
        check_number(result, 0);

      it("then version should be { 0x04, 0x88, 0xad, 0xe4 } (xprv)")
        check(memcmp(buffer, (uint8_t[]){ 0x04, 0x88, 0xad, 0xe4 }, 4) == 0);

      it("then depth should be 0")
        check(memcmp((buffer + 4), (uint8_t[]){ 0x00 }, 1) == 0);

      it("then parent fingerprint should be { 0x0, 0x0, 0x0, 0x0 }")
        check(memcmp((buffer + 4 + 1), (uint8_t[]){ 0x0, 0x0, 0x0, 0x0 }, 4) == 0);

      it("then index should be { 0x0, 0x0, 0x0, 0x0 }")
        check(memcmp((buffer + 4 + 1 + 4), (uint8_t[]){ 0x0, 0x0, 0x0, 0x0 }, 4) == 0);
    }

    describe("when serializing private key (encoded)") {
      char buffer[1024];
      static size_t size = sizeof(buffer);
      static int result = -1;

      before_each() {
        result = bip32_key_serialize(&private_key, true, (uint8_t*)buffer, &size);
      }

      it("then should not return error")
        check_number(result, 0);

      it("then should return the correct xprv* string")
	check_str(buffer, vectors[0].masterkey);
    }

    describe("when deserializing encoded private key") {
      static bip32_key_t deserialized_key;
      static int result = -1;
      before() {
        result = bip32_key_deserialize(&deserialized_key, vectors[0].masterkey);
      }
      it("then should not return error")
        check_number(result, 0);

      it ("then should create expected key")
        check(memcmp(&private_key, &deserialized_key, sizeof(bip32_key_t)) == 0);
    }

    describe("when serialize public key (encoded)") {
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

    describe("when deserializing encoded public key") {
      static bip32_key_t deserialized_key;
      static int result = -1;

      before() {
        bip32_key_init_public_from_private_key(&public_key, &private_key);
        result = bip32_key_deserialize(&deserialized_key, vectors[0].publickey);
      }

      it("then should not fail deserialize")
        check_number(result, 0);

      it ("then should create expected key")
          check(memcmp(&public_key, &deserialized_key, sizeof(bip32_key_t)) == 0);
    }
  }

  context("key identifiers") {
    static bip32_key_t private_key;
    static bip32_key_t public_key;
    static int result = -1;

    before() {
      bip32_key_init_from_entropy(&private_key, vectors[0].seed, sizeof(vectors[0].seed));
      bip32_key_init_public_from_private_key(&public_key, &private_key);
    }

    describe("when creating identifier from private key") {
      static bip32_key_identifier_t ident;
      it("then should return non error")
        check(bip32_key_identifier_init_from_key(&ident, &private_key) == 0);

      describe("and generating a fingerprint") {
        static uint32_t fingerprint;
        static int result;

        before() {
          result = bip32_key_identifier_fingerprint(&ident, &fingerprint);
        }

        it("then should not return error")
          check_number(result, 0);

        it("then should generate expected fingerprint")
          check_number_hex(fingerprint, 0xb8688df1);
      }
    }

    describe("when creating identifier from public key") {
      static bip32_key_identifier_t ident;
      it("then should not return error")
        check(bip32_key_identifier_init_from_key(&ident, &public_key) == 0);

      describe("and generating a fingerprint") {
        static uint32_t fingerprint;
        static int result;

        before() {
          result = bip32_key_identifier_fingerprint(&ident, &fingerprint);
        }

        it("then should not return error")
          check_number(result, 0);

        it("then should generate expected fingerprint")
          check_number_hex(fingerprint, 0xb8688df1);
      }
    }

    describe("when creating identifier from public key") {
      static bip32_key_identifier_t ident;
      static uint32_t fingerprint;
      static int result;

      it("then should not return error")
        check(bip32_key_identifier_init_from_key(&ident, &public_key) == 0);
    }
  }
}
