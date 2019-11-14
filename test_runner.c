#include "blake2b.h"
#include "mmr.h"
#include <stdio.h>
#include <stdlib.h>

#define MMR_TREE_LEAVES 1000

static int tests_run = 0;
static uint8_t shared_mmr_tree[MMR_TREE_LEAVES * MMR_TREE_LEAVES][HASH_SIZE];
static uint64_t shared_mmr_size = 0;

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

/* helper function */
/* return hexed hash */
char *hex(uint8_t *hash) {
  char *buf = (char *)malloc(sizeof(char) * 128);
  for (int i = 0; i < HASH_SIZE; i++) {
    sprintf(&buf[i * 2], "%02x", hash[i]);
  }
  return buf;
}

void merge_hash(uint8_t dst[HASH_SIZE], uint8_t left_hash[HASH_SIZE],
                uint8_t right_hash[HASH_SIZE]) {
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, HASH_SIZE);
  blake2b_update(&blake2b_ctx, left_hash, HASH_SIZE);
  blake2b_update(&blake2b_ctx, right_hash, HASH_SIZE);
  blake2b_final(&blake2b_ctx, dst, HASH_SIZE);
  return;
}

/* initialize shared mmr tree */
int initialize_shared_tree() {
  MMRContext ctx;
  int ret = mmr_initialize_context(
      &ctx, 0, shared_mmr_tree, MMR_TREE_LEAVES * MMR_TREE_LEAVES, merge_hash);
  if (ret != 0) {
    return -1;
  }
  for (uint64_t i = 0; i < MMR_TREE_LEAVES; i++) {
    uint8_t leaf[HASH_SIZE];
    memset(leaf, 0, HASH_SIZE);
    memcpy(leaf, &i, sizeof(uint64_t));
    if (mmr_push(&ctx, leaf) != 0) {
      return -2;
    }
  }
  shared_mmr_size = ctx.mmr_size;
  return 0;
}

/* unit tests */
int test_merkle_proof() {
  uint8_t item[] = {
      5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  MMRSizePos item_pos = mmr_compute_pos_by_leaf_index(5);
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
  MMRVerifyContext ctx;
  mmr_initialize_verify_context(&ctx, merge_hash);
  mmr_compute_proof_root(&ctx, merkle_root, mmr_size, item, item_pos.pos,
                         proof_items, proof_len);
  int ret = memcmp(root, merkle_root, HASH_SIZE);
  _assert(ret == 0);
  return 0;
}

int test_compute_new_root_from_proof_6() {
  uint8_t item[] = {
      5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  MMRSizePos item_pos = mmr_compute_pos_by_leaf_index(5);
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
  MMRSizePos new_item_pos = mmr_compute_pos_by_leaf_index(6);
  MMRVerifyContext ctx;
  mmr_initialize_verify_context(&ctx, merge_hash);
  mmr_compute_new_root_from_last_leaf_proof(&ctx, new_root, mmr_size, item,
                                            item_pos.pos, proof_items,
                                            proof_len, new_item, new_item_pos);
  int ret = memcmp(new_root, next_root, HASH_SIZE);
  _assert(ret == 0);
  return 0;
}

int test_compute_new_root_from_proof_7() {
  uint8_t item[] = {
      6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  MMRSizePos item_pos = mmr_compute_pos_by_leaf_index(6);
  uint64_t mmr_size = 11;
  uint64_t proof_len = 2;
  uint8_t proof_items[][HASH_SIZE] = {
      {
          169, 85, 202, 90,  73,  91,  221, 22,  127, 98,  83,
          191, 25, 14,  230, 209, 177, 42,  195, 90,  147, 115,
          37,  90, 161, 179, 166, 152, 202, 100, 45,  75,
      },
      {
          15,  87,  63,  191, 31,  182, 148, 82,  116, 16, 32,
          65,  52,  177, 93,  104, 209, 186, 100, 50,  84, 22,
          199, 173, 150, 238, 133, 217, 94,  61,  66,  60,
      },
  };
  uint8_t next_root[] = {
      47,  5,  175, 44, 42,  42,  94, 157, 107, 239, 26, 221, 232, 39, 116, 135,
      229, 83, 136, 65, 138, 200, 39, 214, 44,  239, 18, 168, 105, 85, 234, 5,
  };
  uint8_t new_root[HASH_SIZE];
  uint8_t new_item[] = {
      7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  MMRSizePos new_item_pos = mmr_compute_pos_by_leaf_index(7);
  MMRVerifyContext ctx;
  mmr_initialize_verify_context(&ctx, merge_hash);
  mmr_compute_new_root_from_last_leaf_proof(&ctx, new_root, mmr_size, item,
                                            item_pos.pos, proof_items,
                                            proof_len, new_item, new_item_pos);
  int ret = memcmp(new_root, next_root, HASH_SIZE);
  _assert(ret == 0);
  return 0;
}

int test_leaf_index_to_pos() {
  MMRSizePos pos, expected;

  pos = mmr_compute_pos_by_leaf_index(0);
  expected = (MMRSizePos){1, 0};
  _assert(memcmp(&pos, &expected, sizeof(MMRSizePos)) == 0);

  pos = mmr_compute_pos_by_leaf_index(1);
  expected = (MMRSizePos){3, 1};
  _assert(memcmp(&pos, &expected, sizeof(MMRSizePos)) == 0);

  pos = mmr_compute_pos_by_leaf_index(2);
  expected = (MMRSizePos){4, 3};
  _assert(memcmp(&pos, &expected, sizeof(MMRSizePos)) == 0);
  return 0;
}

int test_mmr() {
  MMRContext ctx;
  int ret =
      mmr_initialize_context(&ctx, shared_mmr_size, shared_mmr_tree,
                             MMR_TREE_LEAVES * MMR_TREE_LEAVES, merge_hash);
  _assert(ret == 0);
  MMRVerifyContext verify_ctx;
  ret = mmr_initialize_verify_context(&verify_ctx, merge_hash);
  _assert(ret == 0);
  uint8_t root[HASH_SIZE];
  ret = mmr_get_root(&ctx, root);
  _assert(ret == 0);
  for (uint64_t i = 0; i < MMR_TREE_LEAVES; i++) {
    uint8_t proof[MMR_TREE_LEAVES][HASH_SIZE];
    size_t proof_len = MMR_TREE_LEAVES;
    uint8_t root2[HASH_SIZE];
    MMRSizePos pos = mmr_compute_pos_by_leaf_index(i);
    ret = mmr_gen_proof(&ctx, proof, &proof_len, pos.pos);
    _assert(ret == 0);
    uint8_t leaf[HASH_SIZE];
    memset(leaf, 0, HASH_SIZE);
    memcpy(leaf, &i, sizeof(uint64_t));
    mmr_compute_proof_root(&verify_ctx, root2, shared_mmr_size, leaf, pos.pos,
                           proof, proof_len);
    ret = memcmp(root, root2, HASH_SIZE);
    _assert(ret == 0);
  }
  return 0;
}

int test_gen_new_root() { return 0; }

/* end unit tests */

int all_tests() {
  int ret = initialize_shared_tree();
  if (ret != 0) {
    FAIL();
    return ret;
  }
  _verify(test_merkle_proof);
  _verify(test_compute_new_root_from_proof_6);
  _verify(test_compute_new_root_from_proof_7);
  _verify(test_leaf_index_to_pos);
  _verify(test_mmr);

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
