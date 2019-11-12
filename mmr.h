/* Mountain merkle range
 * Reference implementation:
 * https://github.com/nervosnetwork/merkle-mountain-range
 *
 * Copyright 2019 Jiang Jinyang <jjyruby@gmail.com>
 * under MIT license
 */

#ifndef MMR_H
#define MMR_H

#include "assert.h"
#include "stddef.h"
#include "string.h"

#define HASH_SIZE 32

/* types */
typedef struct VerifyContext {
  void (*merge)(uint8_t *dst, uint8_t *right, uint8_t *left);
} VerifyContext;

typedef struct Peaks {
  uint64_t *peaks;
  size_t len;
} Peaks;

typedef struct HeightPos {
  uint32_t height;
  uint64_t pos;
} HeightPos;

typedef struct MMRSizePos {
  uint64_t mmr_size;
  uint64_t pos;
} MMRSizePos;

/* helper functions */

uint64_t parent_offset(uint32_t height) { return 2 << height; }

uint64_t sibling_offset(uint32_t height) { return (2 << height) - 1; }

/* return height 0 pos 0 if can't find a right peak */
HeightPos get_right_peak(uint32_t height, uint64_t pos, uint64_t mmr_size) {
  // move to right sibling pos
  pos += sibling_offset(height);
  // loop until we find a pos in mmr
  while (pos > mmr_size - 1) {
    if (height == 0) {
      HeightPos ret = {0, 0};
      return ret;
    }
    // move to left child
    pos -= parent_offset(height - 1);
    height -= 1;
  }
  HeightPos peak = {height, pos};
  return peak;
}

uint64_t peak_pos_by_height(uint32_t height) { return (1 << (height + 1)) - 2; }

HeightPos left_peak_height_pos(uint64_t mmr_size) {
  uint32_t height = 1;
  uint64_t prev_pos = 0;
  uint64_t pos = peak_pos_by_height(height);
  while (pos < mmr_size) {
    height += 1;
    prev_pos = pos;
    pos = peak_pos_by_height(height);
  }
  HeightPos p = {height - 1, prev_pos};
  return p;
}

/* peaks_buf should at least equals to left_peak.height, to make sure we have
 * enough buf to store peaks.
 */
Peaks get_peaks(uint64_t *peaks_buf, HeightPos left_peak, uint64_t mmr_size) {
  /* After a little thought we can figure out the number of peaks will never
   * greater than MMR height
   * https://github.com/nervosnetwork/merkle-mountain-range#construct
   */
  uint32_t height = left_peak.height;
  uint64_t pos = left_peak.pos;
  size_t i = 0;
  peaks_buf[i++] = pos;
  while (height > 0) {
    HeightPos peak = get_right_peak(height, pos, mmr_size);
    /* no more right peak */
    if (peak.height == 0 && peak.pos == 0) {
      break;
    }
    height = peak.height;
    pos = peak.pos;
    peaks_buf[i++] = pos;
  }
  struct Peaks peaks = {peaks_buf, i};
  return peaks;
}

/* binary search, arr must be a sorted array
 * return -1 if binary search failed, otherwise return index
 */
int binary_search(uint64_t *arr, size_t len, uint64_t target) {
  if (len == 0) {
    return -1;
  }
  int b = 0;
  int e = len;
  while (b + 1 != e) {
    int i = (b + e) / 2;
    if (arr[i] < target) {
      b = i;
    } else if (arr[i] > target) {
      e = i;
    } else {
      return i;
    }
  }
  if (arr[b] == target) {
    return b;
  } else if (e < len && arr[e] == target) {
    return e;
  }
  return -1;
}

/* return number of zeros */
size_t count_zeros(uint64_t n, int only_count_leading) {
  size_t num_zeros = 0;

  for (int i = 63; i >= 0; --i) {
    if ((n & ((uint64_t)1 << (uint64_t)i)) == 0) {
      ++num_zeros;
    } else if (only_count_leading) {
      break;
    }
  }
  return num_zeros;
}

int is_all_one_bits(uint64_t n) {
  return n != 0 && count_zeros(n, 0) == count_zeros(n, 1);
}

uint64_t jump_left(uint64_t pos) {
  size_t bit_length = 64 - count_zeros(pos, 1);
  size_t most_significant_bits = 1 << (bit_length - 1);
  return pos - (most_significant_bits - 1);
}

uint32_t pos_height_in_tree(uint64_t pos) {
  pos += 1;

  while (!is_all_one_bits(pos)) {
    pos = jump_left(pos);
  }

  return 64 - count_zeros(pos, 1) - 1;
}

static uint64_t simple_log2(uint64_t n) {
  unsigned int res = 0;
  while (n >>= 1)
    res++;
  return res;
}

MMRSizePos compute_pos_by_leaf_index(uint64_t index) {
  if (index == 0) {
    MMRSizePos ret = {0, 0};
    return ret;
  }
  // leaf_count
  uint64_t leaves = index + 1;
  uint64_t tree_node_count = 0;
  uint32_t height = 0;
  uint64_t mmr_size = 0;
  while (leaves > 1) {
    // get heighest peak height
    height = simple_log2(leaves);
    // calculate leaves in peak
    uint64_t peak_leaves = (uint32_t)1 << height;
    // heighest positon
    uint64_t sub_tree_node_count = peak_pos_by_height(height) + 1;
    tree_node_count += sub_tree_node_count;
    leaves -= peak_leaves;
    mmr_size += (peak_leaves * 2 - 1);
  }
  // two leaves can construct a new peak, the only valid number of leaves is 0
  // or 1.
  assert(leaves == 0 || leaves == 1);
  if (leaves == 1) {
    // add one pos for remain leaf
    // equals to `tree_node_count - 1 + 1`
    mmr_size += 1;
    MMRSizePos ret = {mmr_size, tree_node_count};
    return ret;
  } else {
    uint64_t pos = tree_node_count - 1;
    MMRSizePos ret = {mmr_size, pos - height};
    return ret;
  }
}

static size_t compute_peak_root(VerifyContext *ctx,
                                uint8_t peak_hash[HASH_SIZE], Peaks peaks,
                                uint64_t *pos, uint8_t proof[][HASH_SIZE],
                                size_t proof_len) {
  size_t i = 0;
  uint32_t height = 0;
  // calculate peak's merkle root
  // return if pos reach a peak pos
  while (1) {
    int idx = binary_search(peaks.peaks, peaks.len, *pos);
    /* end loop if reach a peak or consume all the proof items */
    if (idx >= 0 || i >= proof_len) {
      break;
    }
    uint8_t *pitem = proof[i++];
    // verify merkle path
    uint32_t pos_height = pos_height_in_tree(*pos);
    uint32_t next_height = pos_height_in_tree(*pos + 1);
    if (next_height > pos_height) {
      // we are on right branch
      *pos += 1;
      ctx->merge(peak_hash, pitem, peak_hash);
    } else {
      // we are on left branch
      *pos += parent_offset(height);
      ctx->merge(peak_hash, peak_hash, pitem);
    }
    height += 1;
  }
  return i;
}

/* MMR API */

/* Initialize VerifyContext */

int initialize_verify_context(VerifyContext *ctx,
                              void(merge)(uint8_t *dst, uint8_t *right,
                                          uint8_t *left)) {
  ctx->merge = merge;
  return 0;
}

/* compute root from merkle proof */
void compute_proof_root(VerifyContext *ctx, uint8_t root_hash[HASH_SIZE],
                        uint64_t mmr_size, uint8_t leaf_hash[HASH_SIZE],
                        uint64_t pos, uint8_t proof[][HASH_SIZE],
                        size_t proof_len) {
  HeightPos left_peak = left_peak_height_pos(mmr_size);
  uint64_t peaks_buf[left_peak.height];
  struct Peaks peaks = get_peaks(peaks_buf, left_peak, mmr_size);
  // start from leaf_hash
  memcpy(root_hash, leaf_hash, HASH_SIZE);
  // calculate peak's merkle root
  size_t i = compute_peak_root(ctx, root_hash, peaks, &pos, proof, proof_len);

  // bagging peaks
  // bagging with left peaks if pos is last peak(last pos)
  int bagging_left = pos == mmr_size - 1;
  while (i < proof_len) {
    uint8_t *pitem = proof[i++];
    if (bagging_left) {
      ctx->merge(root_hash, root_hash, pitem);
    } else {
      // we are not in the last peak, so bag with right peaks first
      // notice the right peaks is already bagging into one hash in proof,
      // so after this merge, the remain proofs are always left peaks.
      bagging_left = 1;
      ctx->merge(root_hash, pitem, root_hash);
    }
  }
  return;
}

/* compute a new root from last leaf's merkle proof
 * we got the merkle proof of leaf n, and we want calculate merkle root of n + 1
 * leaves from this.
 * this is kinda triky, but by observe the MMR construction graph we know it is
 * possible. https://github.com/jjyr/merkle-mountain-range#construct
 */
void compute_new_root_from_last_leaf_proof(
    VerifyContext *ctx, uint8_t root_hash[HASH_SIZE], uint64_t mmr_size,
    uint8_t leaf_hash[HASH_SIZE], uint64_t leaf_pos, uint8_t proof[][HASH_SIZE],
    size_t proof_len, uint8_t new_leaf_hash[HASH_SIZE],
    MMRSizePos new_leaf_pos) {
  uint32_t pos_height = pos_height_in_tree(new_leaf_pos.pos);
  uint32_t next_height = pos_height_in_tree(new_leaf_pos.pos + 1);
  if (next_height > pos_height) {
    /* new leaf on right branch */
    uint8_t new_proof[proof_len + 1][HASH_SIZE];
    /* set peak's root and remain proof as new_proof */
    memcpy(new_proof[0], leaf_hash, HASH_SIZE);
    for (int i = 0; i < proof_len; i++) {
      memcpy(new_proof[i + 1], proof[i], HASH_SIZE);
    }
    compute_proof_root(ctx, root_hash, new_leaf_pos.mmr_size, new_leaf_hash,
                       new_leaf_pos.pos, new_proof, proof_len + 1);
  } else {
    /* new leaf on left branch
     * 1. calculate peak's root from last leaf.
     * 2. use peak's root and remain proof as new_proof, then compute_proof_root
     */
    assert(mmr_size + 1 == new_leaf_pos.mmr_size);
    HeightPos left_peak = left_peak_height_pos(mmr_size);
    uint64_t peaks_buf[left_peak.height];
    struct Peaks peaks = get_peaks(peaks_buf, left_peak, mmr_size);
    // start from leaf_hash
    memcpy(root_hash, leaf_hash, HASH_SIZE);
    size_t i =
        compute_peak_root(ctx, root_hash, peaks, &leaf_pos, proof, proof_len);
    /* set peak's root and remain proof as new_proof */
    memcpy(proof[0], root_hash, HASH_SIZE);
    for (int j = i; j < proof_len; j++) {
      memcpy(proof[j - i + 1], proof[j], HASH_SIZE);
    }
    proof_len = proof_len + 1 - i;
    compute_proof_root(ctx, root_hash, new_leaf_pos.mmr_size, new_leaf_hash,
                       new_leaf_pos.pos, proof, proof_len);
  }
}

#endif
