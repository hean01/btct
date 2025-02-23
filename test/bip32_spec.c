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
      static uint8_t buffer[1024];
      static size_t size = sizeof(buffer);
      static int result = -1;

      before_each() {
        result = bip32_key_serialize(&private_key, false, (uint8_t*)buffer, &size);
      }

      it("then not return error")
        check_number(result, 0);

      it("then version should be { 0x04, 0x88, 0xad, 0xe4 } (xprv)")
        check(memcmp(buffer, (uint8_t[]){ 0x04, 0x88, 0xad, 0xe4 }, 4) == 0);

      it("then depth should be 1")
        check(memcmp((buffer + 4), (uint8_t[]){ 0x0 }, 1) == 0);

      it("then parent fingerprint should be { 0x0, 0x0, 0x0, 0x0 }")
        check(memcmp((buffer + 4 + 1), (uint8_t[]){ 0x0, 0x0, 0x0, 0x0 }, 4) == 0);

      it("then index should be { 0x0, 0x0, 0x0, 0x0 }")
        check(memcmp((buffer + 4 + 1 + 4), (uint8_t[]){ 0x0, 0x0, 0x0, 0x0 }, 4) == 0);
    }

    describe("when serializing derived hardend key key (m/0')") {
      static bip32_key_t child;
      static uint8_t buffer[1024];
      static size_t size = sizeof(buffer);
      static int result = -1;

      before() {
        result = bip32_key_derive_child_key(&private_key, 2<<30, &child);
        result = bip32_key_serialize(&child, false, (uint8_t*)buffer, &size);
      }

      it("then not return error")
        check_number(result, 0);

      it("then version should be { 0x04, 0x88, 0xad, 0xe4 } (xprv)")
        check(memcmp(buffer, (uint8_t[]){ 0x04, 0x88, 0xad, 0xe4 }, 4) == 0);

      it("then depth should be 1")
        check(memcmp((buffer + 4), (uint8_t[]){ 0x01 }, 1) == 0);

      it("then parent fingerprint should be { 0xb8, 0x68, 0x8d, 0xf1}")
        check(memcmp((buffer + 4 + 1), (uint8_t[]){ 0xb8, 0x68, 0x8d, 0xf1 }, 4) == 0);

      it("then index should be { 0x80, 0x0, 0x0, 0x0 }")
        check(memcmp((buffer + 4 + 1 + 4), (uint8_t[]){ 0x80, 0x0, 0x0, 0x0 }, 4) == 0);
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

  context("key deriviation") {
    static bip32_key_t private_key;
    static bip32_key_t public_key;
    static int result = -1;

    before() {
      bip32_key_init_from_entropy(&private_key, vectors[0].seed, sizeof(vectors[0].seed));
      bip32_key_init_public_from_private_key(&public_key, &private_key);
    }

    context("given a known private key") {

      describe("when derive a hardend account child private key m/'0") {
        static bip32_key_t child;
        static int result = -1;
        before() {
          result = bip32_key_derive_child_key(&private_key, 2<<30, &child);
        }

        it("then should return non error")
          check_number(result, 0);

        it("then should be a private key")
          check(child.public == false);

        it("then depth should be 1")
          check_number(child.depth, 1);

        it("then parent fingerprint should be { 0xb8, 0x68, 0x8d, 0xf1}")
          check(memcmp(child.parent_fingerprint, (uint8_t[]){ 0xb8, 0x68, 0x8d, 0xf1 }, 4) == 0);

        it("then index should be 0x80000000")
          check_number_hex(child.index, 0x80000000);

        describe("and serialize child key (encoded)") {
          static bip32_key_t child;
          static char buffer[1024];
          static size_t size = sizeof(buffer);
          before() {
            bip32_key_derive_child_key(&private_key, 0x80000000, &child);
            bip32_key_serialize(&child, true, (uint8_t*)buffer, &size);
          }
          it("should return the expected xprv9vFm...xEjA string")
            check_str(buffer, "xprv9vFm7KXyXnwkE9E1ETdKZWq9n5WqMP8eomCbJj3cAvwVErBjeq4U7Zw9EVXXABvrSFqik5ZfWH1VbSVCvmvVYD9ox31YnzmRkrXU22mxEjA");
        }
      }

      describe("when derive a hardend account child private key m/'0/'1") {
        static bip32_key_t child_idx1, child_idx2;
        static int result = -1;
        before() {
          result = bip32_key_derive_child_key(&private_key, 0x80000000, &child_idx1);
          result = bip32_key_derive_child_key(&child_idx1, 0x80000001, &child_idx2);
        }

        it("then should return non error")
          check_number(result, 0);

        it("then should be a private key")
          check(child_idx2.public == false);

        it("then depth should be 2")
          check_number(child_idx2.depth, 2);

        it("then parent fingerprint should be { 0xc8, 0x79, 0x95, 0x0c}")
          check(memcmp(child_idx2.parent_fingerprint, (uint8_t[]){ 0xc8, 0x79, 0x95, 0x0c }, 4) == 0);

        it("then index should be 0x80000001")
          check_number_hex(child_idx2.index, 0x80000001);

        describe("and serialize child key (encoded)") {
          static char buffer[1024];
          static size_t size = sizeof(buffer);
          before() {
            bip32_key_serialize(&child_idx2, true, (uint8_t*)buffer, &size);
          }
          it("should return the expected xprv9xFk...B8WH string")
            check_str(buffer, "xprv9xFkEEMD49vRgSHunvh2tyzK1ByWFygQEEBiSAUxmRqaE27AS73Hu9AV3Pb5zj1noVtAcySiqnkYC5VXi1wBoZFcRTGXCsiW6BwbfbHB8WH");
        }
      }

      describe("when derive a normal account child private key m/'0/1") {
        static bip32_key_t child_idx1, child_idx2;
        static int result = -1;
        before() {
          result = bip32_key_derive_child_key(&private_key, 0x80000000, &child_idx1);
          result = bip32_key_derive_child_key(&child_idx1, 1, &child_idx2);
        }

        it("then should return non error")
          check_number(result, 0);

        it("then should be a private key")
          check(child_idx2.public == false);

        it("then depth should be 2")
          check_number(child_idx2.depth, 2);

        it("then parent fingerprint should be { 0xc8, 0x79, 0x95, 0x0c}")
          check(memcmp(child_idx2.parent_fingerprint, (uint8_t[]){ 0xc8, 0x79, 0x95, 0x0c }, 4) == 0);

        it("then index should be 1")
          check_number(child_idx2.index, 1);

        describe("and serialize child key (encoded)") {
          static char buffer[1024];
          static size_t size = sizeof(buffer);
          before() {
            bip32_key_serialize(&child_idx2, true, (uint8_t*)buffer, &size);
          }
          it("should return the expected xprv9xFk...b13t string")
            check_str(buffer, "xprv9xFkEEM4iVPTUh9qEBen68GJ9ZfL5okMUwH6o9td98zu3HPduhYqpqybE6po8NuKA1e43opFjZUJn4p1xwanNf3RJQU3u5PRqz8aA8wb13t");
        }
      }

      describe("when derive a normal account child private key using path derive m/0'/1'") {
        static bip32_key_t child;
        static int result = -1;
        before() {
          result = bip32_key_derive_child_by_path(&private_key, "m/0'/1'", &child);
        }

        it("then should return non error")
          check_number(result, 0);

        it("then should be a private key")
          check(child.public == false);

        it("then depth should be 2")
          check_number(child.depth, 2);

        it("then parent fingerprint should be { 0xc8, 0x79, 0x95, 0x0c}")
          check(memcmp(child.parent_fingerprint, (uint8_t[]){ 0xc8, 0x79, 0x95, 0x0c }, 4) == 0);

        it("then index should be 1")
          check_number_hex(child.index, 0x80000001);

        describe("and serialize child key (encoded)") {
          static char buffer[1024];
          static size_t size = sizeof(buffer);
          before() {
            bip32_key_serialize(&child, true, (uint8_t*)buffer, &size);
          }
          it("should return the expected xprv9xFk...B8WH string")
            check_str(buffer, "xprv9xFkEEMD49vRgSHunvh2tyzK1ByWFygQEEBiSAUxmRqaE27AS73Hu9AV3Pb5zj1noVtAcySiqnkYC5VXi1wBoZFcRTGXCsiW6BwbfbHB8WH");
        }
      }
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
        check(bip32_key_identifier_init_from_key(ident, &private_key) == 0);

      describe("and generating a fingerprint") {
        static uint8_t fingerprint[4];
        static int result;

        before() {
          result = bip32_key_identifier_fingerprint(ident, fingerprint);
        }

        it("then should not return error")
          check_number(result, 0);

        it("then should generate expected fingerprint")
          check(memcmp(fingerprint, (uint8_t[]){0xb8, 0x68, 0x8d, 0xf1}, 4) == 0);
      }
    }

    describe("when creating identifier from public key") {
      static bip32_key_identifier_t ident;
      it("then should not return error")
        check(bip32_key_identifier_init_from_key(ident, &public_key) == 0);

      describe("and generating a fingerprint") {
        static uint8_t fingerprint[4];
        static int result;

        before() {
          result = bip32_key_identifier_fingerprint(ident, fingerprint);
        }

        it("then should not return error")
          check_number(result, 0);

        it("then should generate expected fingerprint")
          check(memcmp(fingerprint, (uint8_t[]){0xb8, 0x68, 0x8d, 0xf1}, 4) == 0);
      }
    }

    describe("when creating identifier from public key") {
      static bip32_key_identifier_t ident;
      static uint32_t fingerprint;
      static int result;

      it("then should not return error")
        check(bip32_key_identifier_init_from_key(ident, &public_key) == 0);
    }
  }
}
