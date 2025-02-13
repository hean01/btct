#include "./bdd-for-c.h"
#include "./test_vectors.h"
#include "../src/bip85.h"

#define check_str(got, expected) check(strcmp(got, expected) == 0, "expected string '%s' got '%s'", expected, got)
#define check_number(got, expected) check(got == expected, "expected '%d' got '%d'", expected, got)

static void
str_array_to_str(char **array, size_t size, char *delimiter, char *result)
{
  for (size_t i = 0; i < size; i++) {
    strcat(result, array[i]);
    if (i != size - 1)
      strcat(result, delimiter);
  }
}

spec("bip85") {

  context("Given known masterkey") {
    static bip32_key_t key;
    before() {
      bip32_key_deserialize(&key, "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb");
    }

    describe("when deriving entropy using subpath 0'/0'") {
      static uint8_t entropy[64] = {0};
      static uint8_t expected_entropy[] = {
              0xef, 0xec, 0xfb, 0xcc, 0xff, 0xea, 0x31, 0x32, 0x14, 0x23, 0x2d, 0x29, 0xe7, 0x15, 0x63, 0xd9,
              0x41, 0x22, 0x9a, 0xfb, 0x43, 0x38, 0xc2, 0x1f, 0x95, 0x17, 0xc4, 0x1a, 0xaa, 0x0d, 0x16, 0xf0,
              0x0b, 0x83, 0xd2, 0xa0, 0x9e, 0xf7, 0x47, 0xe7, 0xa6, 0x4e, 0x8e, 0x2b, 0xd5, 0xa1, 0x48, 0x69,
              0xe6, 0x93, 0xda, 0x66, 0xce, 0x94, 0xac, 0x2d, 0xa5, 0x70, 0xab, 0x7e, 0xe4, 0x86, 0x18, 0xf7
      };
      static int result = -1;
      before() {
        result = bip85_entropy_from_key(&key, "0'/0'", entropy);
      }

      it("then should not return error")
        check_number(0, result);

      it("then should return expected entropy")
        check(memcmp(expected_entropy, entropy, 64) == 0);
    }

    describe("when deriving entropy using subpath 0'/1'") {
      static uint8_t entropy[64] = {0};
      static uint8_t expected_entropy[] = {
        0x70, 0xc6, 0xe3, 0xe8, 0xeb, 0xee, 0x8d, 0xc4, 0xc0, 0xdb, 0xba, 0x66, 0x07, 0x68, 0x19, 0xbb,
        0x8c, 0x09, 0x67, 0x25, 0x27, 0xc4, 0x27, 0x7c, 0xa8, 0x72, 0x95, 0x32, 0xad, 0x71, 0x18, 0x72,
        0x21, 0x8f, 0x82, 0x69, 0x19, 0xf6, 0xb6, 0x72, 0x18, 0xad, 0xde, 0x99, 0x01, 0x8a, 0x6d, 0xf9,
        0x09, 0x5a, 0xb2, 0xb5, 0x8d, 0x80, 0x3b, 0x5b, 0x93, 0xec, 0x98, 0x02, 0x08, 0x5a, 0x69, 0x0e
      };

      static int result = -1;
      before() {
        result = bip85_entropy_from_key(&key, "0'/1'", entropy);
      }

      it("then should not return error")
        check_number(0, result);

      it("then should return expected entropy")
        check(memcmp(expected_entropy, entropy, 64) == 0);
    }

    context("application bip39") {
      describe("when generating 12 english word index 0") {
        static char **words;
        static size_t word_cnt;
        static char *expected_words[] = {
          "girl", "mad", "pet", "galaxy", "egg", "matter", "matrix", "prison",
          "refuse", "sense", "ordinary", "nose"};
        before() {
          bip85_application_bip39(&key, 0, 12, 0, &words, &word_cnt);
        }

        it("then it should generate correct 12 words")
          check_number(word_cnt, 12);

        it("then it should generate correct mnemonic phrase") {
          for (size_t i=0; i < word_cnt; i++) {
            check_str(words[i], expected_words[i]);
          }
        }
      }

      describe("when generating 18 english word index 0") {
        static char **words;
        static size_t word_cnt;
        static char *expected_words[] = {
          "near", "account", "window", "bike", "charge", "season", "chef", "number",
          "sketch", "tomorrow", "excuse", "sniff", "circle", "vital", "hockey", "outdoor",
          "supply", "token"
        };
        before() {
          bip85_application_bip39(&key, 0, 18, 0, &words, &word_cnt);
        }

        it("then it should generate correct 18 words")
          check_number(word_cnt, 18);

        it("then it should generate correct mnemonic phrase") {
          for (size_t i=0; i < word_cnt; i++) {
            check_str(words[i], expected_words[i]);
          }
        }
      }

      describe("when generating 24 english word index 0") {
        static char **words;
        static size_t word_cnt;
        static char *expected_words[] = {
          "puppy", "ocean", "match", "cereal", "symbol", "another", "shed", "magic",
          "wrap", "hammer", "bulb", "intact", "gadget", "divorce", "twin", "tonight",
          "reason", "outdoor", "destroy", "simple", "truth", "cigar", "social", "volcano"
        };
        before() {
          bip85_application_bip39(&key, 0, 24, 0, &words, &word_cnt);
        }

        it("then it should generate correct 18 words")
          check_number(word_cnt, 24);

        it("then it should generate correct mnemonic phrase") {
          for (size_t i=0; i < word_cnt; i++) {
            check_str(words[i], expected_words[i]);
          }
        }
      }
    }
  }
}
