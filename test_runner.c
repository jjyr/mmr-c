#include "mmr.h"
#include <stdio.h>
#include <stdlib.h>

static int tests_run = 0;

#define FAIL() printf("\nfailure in %s() line %d\n", __func__, __LINE__)
#define _assert(test)                                                          \
  do {                                                                         \
    if (!(test)) {                                                             \
      FAIL();                                                                  \
      return 1;                                                                \
    }                                                                          \
  } while (0)
#define _verify(test)                                                          \
  do {                                                                         \
    int r = test();                                                            \
    tests_run++;                                                               \
    if (r)                                                                     \
      return r;                                                                \
  } while (0)

/* return hexed hash */
char *hex(uint8_t *hash) {
  char *buf = (char *)malloc(sizeof(char) * 128);
  for (int i = 0; i < HASH_SIZE; i++) {
    sprintf(&buf[i * 2], "%02x", hash[i]);
  }
  return buf;
}

/* unit tests */
int merkle_proof() {
  uint8_t item[] = {
      5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  MMRSizePos item_pos = compute_pos_by_leaf_index(5);
  uint64_t mmr_size = 22;
  uint8_t root[] = {213, 43,  252, 232, 123, 68, 130, 66,  209, 240, 17,
                    45,  15,  70,  56,  85,  40, 155, 74,  38,  137, 175,
                    56,  155, 135, 242, 240, 61, 160, 154, 103, 243};
  uint64_t proof_len = 4;
  uint8_t proof_items[][HASH_SIZE] = {
      {
          4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      },
      {
          241, 39,  155, 74,  33,  122, 233, 24,  212, 112, 138,
          36,  197, 251, 173, 189, 250, 124, 152, 2,   159, 247,
          125, 60,  9,   89,  197, 236, 23,  3,   127, 80,
      },
      {
          15,  87,  63,  191, 31,  182, 148, 82,  116, 16, 32,
          65,  52,  177, 93,  104, 209, 186, 100, 50,  84, 22,
          199, 173, 150, 238, 133, 217, 94,  61,  66,  60,
      },
      {
          132, 165, 242, 188, 68,  94,  205, 6,   235, 67,  142,
          224, 105, 204, 213, 3,   233, 123, 229, 98,  253, 122,
          217, 56,  249, 76,  221, 98,  48,  150, 138, 17,
      },
  };
  uint8_t merkle_root[HASH_SIZE];
  compute_proof_root(merkle_root, mmr_size, item, item_pos.pos, proof_items,
                     proof_len);
  int ret = memcmp(root, merkle_root, HASH_SIZE);
  _assert(ret == 0);
  return 0;
}

int compute_new_root_from_merkle_proof() {
  uint8_t item[] = {
      5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  MMRSizePos item_pos = compute_pos_by_leaf_index(5);
  uint64_t mmr_size = 10;
  uint64_t proof_len = 2;
  uint8_t proof_items[][HASH_SIZE] = {
      {
          4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      },
      {
          15,  87,  63,  191, 31,  182, 148, 82,  116, 16, 32,
          65,  52,  177, 93,  104, 209, 186, 100, 50,  84, 22,
          199, 173, 150, 238, 133, 217, 94,  61,  66,  60,
      },
  };
  uint8_t next_root[] = {
      220, 66,  69,  25,  60,  142, 221, 129, 22,  214, 67,
      112, 63,  184, 123, 163, 53,  43,  227, 129, 16,  110,
      148, 240, 148, 158, 67,  103, 152, 100, 71,  134,
  };
  uint8_t new_root[HASH_SIZE];
  uint8_t new_item[] = {
      6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  MMRSizePos new_item_pos = compute_pos_by_leaf_index(6);
  compute_new_root_from_last_leaf_proof(new_root, mmr_size, item, item_pos.pos,
                                        proof_items, proof_len, new_item,
                                        new_item_pos);
  int ret = memcmp(new_root, next_root, HASH_SIZE);
  _assert(ret == 0);
  return 0;
}
/* end unit tests */

int all_tests() {
  _verify(merkle_proof);
  _verify(compute_new_root_from_merkle_proof);
  return 0;
}

int main(int argc, char **argv) {
  int result = all_tests();
  if (result == 0) {
    printf("ALL PASSED\n");
  }
  printf("Tests run: %d\n", tests_run);
  return result;
}
