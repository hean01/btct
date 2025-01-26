#include "./bdd-for-c.h"
#include "./test_vectors.h"
#include "../src/bip39.h"

#define check_str(got, expected) check(strcmp(got, expected) == 0, "expected string '%s' got '%s'", expected, got)
#define check_number(got, expected) check(got == expected, "expected '%d' got '%d'", expected, got)

spec("bip39") {
  static bip39_t ctx;

  context("given generating mnemonic seed phrase") {
    static char **words;
    static size_t word_cnt;
    before_each() {
      bip39_init(&ctx);
    }

    describe("when using 32bit entropy") {
      static uint8_t seed[] = {0,0,0,0};
      it("then it should fail")
	check(bip39_to_mnemonics(&ctx, seed, sizeof(seed)*8, &words, &word_cnt) != 0);
    }


    describe("when using a known 128bit entropy") {
      it("then it should succeed")
	check(bip39_to_mnemonics(&ctx, vectors[0].entropy, 16*8, &words, &word_cnt) == 0);
      it("then it should generate correct 12 mnemonics")
	check_number(word_cnt, 12);
      it("then it should generate correct mnemonic phrase") {
	for (size_t i=0; i < word_cnt; i++) {
	  check_str(words[i], vectors[0].mnemonics[i]);
	}
      }
    }

    describe("when using a known 192bit entropy") {
      it("then it should succeed")
	check(bip39_to_mnemonics(&ctx, vectors[1].entropy, 24*8, &words, &word_cnt) == 0);
      it("then it should generate correct 18 mnemonics")
	check_number(word_cnt, 18);
      it("then it should generate correct mnemonic phrase") {
	for (size_t i=0; i < word_cnt; i++) {
	  check_str(words[i], vectors[1].mnemonics[i]);
	}
      }
    }

    describe("when using a known 256bit entropy") {
      it("then it should succeed")
	check(bip39_to_mnemonics(&ctx, vectors[2].entropy, 32*8, &words, &word_cnt) == 0);
      it("then it should generate correct 24 mnemonics")
	check_number(word_cnt, 24);
      it("then it should generate correct mnemonic phrase") {
	for (size_t i=0; i < word_cnt; i++) {
	  check_str(words[i], vectors[2].mnemonics[i]);
	}
      }
    }
  }
}
