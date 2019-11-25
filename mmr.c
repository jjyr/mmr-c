/* Mountain merkle range
 * Reference implementation:
 * https://github.com/nervosnetwork/merkle-mountain-range
 *
 * Copyright 2019 Jiang Jinyang <jjyruby@gmail.com>
 * under MIT license
 */

#include "mmr.h"
#include "assert.h"
#include "stddef.h"
#include "string.h"

/* helper functions */

/* calculate offset of parent position by height */
static uint64_t parent_offset(uint32_t height) { return 2 << height; }

/* calculate offset of sibling position by height */
static uint64_t sibling_offset(uint32_t height) { return (2 << height) - 1; }

/* get right peak from a peak,
 * return height 0 pos 0 if can't find a right peak
 */
static MMRHeightPos get_right_peak(MMRHeightPos peak_pos, uint64_t mmr_size) {
  uint64_t pos = peak_pos.pos;
  uint32_t height = peak_pos.height;
  // move to right sibling pos
  pos += sibling_offset(height);
  // loop until we find a pos in mmr
  while (pos > mmr_size - 1) {
    if (height == 0) {
      MMRHeightPos ret = {0, 0};
      return ret;
    }
    // move to left child
    pos -= parent_offset(height - 1);
    height -= 1;
  }
  MMRHeightPos peak = {height, pos};
  return peak;
}

static uint64_t left_peak_pos_by_height(uint32_t height) {
  return (1 << (height + 1)) - 2;
}

static MMRHeightPos left_peak_height_pos(uint64_t mmr_size) {
  uint32_t height = 1;
  uint64_t prev_pos = 0;
  uint64_t pos = left_peak_pos_by_height(height);
  while (pos < mmr_size) {
    height += 1;
    prev_pos = pos;
    pos = left_peak_pos_by_height(height);
  }
  MMRHeightPos p = {height - 1, prev_pos};
  return p;
}

/* peaks_buf should at least equals to left_peak.height, to make sure we have
 * enough buf to store peaks.
 */
static MMRPeaks get_peaks(uint64_t peaks_buf[HASH_SIZE], MMRHeightPos left_peak,
                          uint64_t mmr_size) {
  /* After a little thought we can figure out the number of peaks will never
   * greater than MMR height
   * https://github.com/nervosnetwork/merkle-mountain-range#construct
   */
  size_t i = 0;
  peaks_buf[i++] = left_peak.pos;
  while (left_peak.height > 0) {
    MMRHeightPos right_peak = get_right_peak(left_peak, mmr_size);
    /* no more right peak */
    if (right_peak.height == 0 && right_peak.pos == 0) {
      break;
    }
    left_peak = right_peak;
    peaks_buf[i++] = left_peak.pos;
  }
  struct MMRPeaks peaks = {peaks_buf, i};
  return peaks;
}

/* binary search, arr must be a sorted array
 * return -1 if binary search failed, otherwise return index
 */
static int binary_search(uint64_t *arr, size_t len, uint64_t target) {
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
static size_t count_zeros(uint64_t n, int only_count_leading) {
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

static int is_all_one_bits(uint64_t n) {
  return n != 0 && count_zeros(n, 0) == count_zeros(n, 1);
}

static uint64_t jump_left(uint64_t pos) {
  size_t bit_length = 64 - count_zeros(pos, 1);
  size_t most_significant_bits = 1 << (bit_length - 1);
  return pos - (most_significant_bits - 1);
}

static uint32_t pos_height_in_tree(uint64_t pos) {
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

static int bag_rhs_peaks(MMRContext *ctx, uint8_t dst[HASH_SIZE],
                         uint64_t skip_pos, MMRPeaks *peaks) {
  uint8_t peaks_elems[peaks->len][HASH_SIZE];
  size_t len = 0;
  for (int i = 0; i < peaks->len; i++) {
    uint64_t pos = peaks->peaks[i];
    if (pos > skip_pos) {
      memcpy(peaks_elems[len++], ctx->tree_buf[pos], HASH_SIZE);
    }
  }

  /* no peaks to bag */
  if (len < 1) {
    return -1;
  }

  while (len > 1) {
    uint8_t *right = peaks_elems[--len];
    uint8_t *left = peaks_elems[--len];
    ctx->merge(peaks_elems[len++], right, left);
  }
  memcpy(dst, peaks_elems[0], HASH_SIZE);
  return 0;
}

static size_t compute_peak_root(MMRVerifyContext *ctx,
                                uint8_t peak_hash[HASH_SIZE], MMRPeaks peaks,
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

/* calculate MMRSizePos from leaf index,
 * mmr_size is the size of mmr when index is the last leaf,
 * pos is the position of leaf in internal mmr.
 */
MMRSizePos mmr_compute_pos_by_leaf_index(uint64_t index) {
  if (index == 0) {
    MMRSizePos ret = {1, 0};
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
    uint64_t sub_tree_node_count = left_peak_pos_by_height(height) + 1;
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

/* Initialize MMRContext
 * mmr_size: the current size of mmr, for a empty MMR it's 0
 * tree_buf: an array of 32bytes buf, used to store mmr internal nodes
 * tree_buf_size: the size of tree_buf, mmr_size will never greater than
 * tree_buf_size.
 * merge: a function to merge left node hash and right node hash
 */
int mmr_initialize_context(MMRContext *ctx, uint64_t mmr_size,
                           uint8_t tree_buf[][HASH_SIZE],
                           uint64_t tree_buf_size,
                           void(merge)(uint8_t dst[HASH_SIZE],
                                       uint8_t right[HASH_SIZE],
                                       uint8_t left[HASH_SIZE])) {
  if (mmr_size > tree_buf_size) {
    return -1;
  }
  ctx->mmr_size = mmr_size;
  ctx->tree_buf = tree_buf;
  ctx->tree_buf_size = tree_buf_size;
  ctx->merge = merge;
  return 0;
}

/* push a leaf into mmr
 * leaf: a 32 bytes hash represented leaf
 */
int mmr_push(MMRContext *ctx, uint8_t leaf[HASH_SIZE]) {
  uint64_t pos = ctx->mmr_size;
  if (pos >= ctx->tree_buf_size) {
    return -1;
  }
  ctx->tree_buf[pos][0] = 1;
  memcpy(ctx->tree_buf[pos], leaf, HASH_SIZE);
  uint32_t height = 0;

  uint64_t i = pos;
  while (pos_height_in_tree(i + 1) > height) {
    i++;
    if (i >= ctx->tree_buf_size) {
      return -1;
    }
    uint64_t left_pos = i - parent_offset(height);
    uint64_t right_pos = left_pos + sibling_offset(height);
    uint8_t *left = ctx->tree_buf[left_pos];
    uint8_t *right = ctx->tree_buf[right_pos];
    ctx->merge(ctx->tree_buf[i], left, right);
    height++;
  }
  ctx->mmr_size = i + 1;
  return 0;
}

/* get merkle root,
 * return -1 if mmr_size is 0
 * dst: a 32 bytes buf to receive merkle root
 */
int mmr_get_root(MMRContext *ctx, uint8_t dst[HASH_SIZE]) {
  if (ctx->mmr_size == 0) {
    return -1;
  } else if (ctx->mmr_size == 1) {
    memcpy(dst, ctx->tree_buf[0], HASH_SIZE);
    return 0;
  }
  MMRHeightPos left_peak = left_peak_height_pos(ctx->mmr_size);
  uint64_t peaks_buf[left_peak.height];
  MMRPeaks peaks = get_peaks(peaks_buf, left_peak, ctx->mmr_size);
  return bag_rhs_peaks(ctx, dst, 0, &peaks);
}

/* generate merkle proof
 * return -1 if proof length is not enough to receive the proof
 * proof: a array of 32 bytes buf to receive merkle proof
 * proof_max_len: length of proof buf, will be set to the actual len of proof.
 * pos: position of leaf
 */
int mmr_gen_proof(MMRContext *ctx, uint8_t proof[][HASH_SIZE],
                  size_t *proof_max_len, uint64_t pos) {
  uint32_t height = 0;
  size_t proof_len = 0;
  while (pos < ctx->mmr_size) {
    uint32_t pos_height = pos_height_in_tree(pos);
    uint32_t next_height = pos_height_in_tree(pos + 1);
    uint64_t sib_pos, next_pos;
    if (next_height > pos_height) {
      // we are on right branch
      sib_pos = pos - sibling_offset(height);
      next_pos = pos + 1;
    } else {
      sib_pos = pos + sibling_offset(height);
      next_pos = pos + parent_offset(height);
    }

    if (sib_pos > ctx->mmr_size - 1) {
      break;
    }
    if (proof_len >= *proof_max_len) {
      return -1;
    }
    memcpy(proof[proof_len++], ctx->tree_buf[sib_pos], HASH_SIZE);
    pos = next_pos;
    height++;
  }
  /* gen merkle proof of the peak */
  MMRHeightPos left_peak = left_peak_height_pos(ctx->mmr_size);
  uint64_t peaks_buf[left_peak.height];
  MMRPeaks peaks = get_peaks(peaks_buf, left_peak, ctx->mmr_size);
  if (proof_len >= *proof_max_len) {
    return -1;
  }
  /* bagging rhs peak */
  int ret = bag_rhs_peaks(ctx, proof[proof_len], pos, &peaks);
  if (ret == 0) {
    proof_len++;
  }
  /* put left peaks to proof */
  for (int i = peaks.len - 1; i >= 0; i--) {
    uint64_t peak_pos = peaks.peaks[i];
    if (peak_pos < pos) {
      if (proof_len >= *proof_max_len) {
        return -1;
      }
      memcpy(proof[proof_len++], ctx->tree_buf[peak_pos], HASH_SIZE);
    }
  }
  *proof_max_len = proof_len;
  return 0;
}

/* Initialize MMRVerifyContext
 * merge: a function to merge left node hash and right node hash
 */
int mmr_initialize_verify_context(MMRVerifyContext *ctx,
                                  void(merge)(uint8_t dst[HASH_SIZE],
                                              uint8_t right[HASH_SIZE],
                                              uint8_t left[HASH_SIZE])) {
  ctx->merge = merge;
  return 0;
}

/* compute root from merkle proof
 * root_hash: a 32 bytes buf to receive root hash
 * mmr_size: size of the mmr to generate this proof
 * leaf_hash: 32 bytes hash of leaf
 * pos: position of the leaf
 * proof: an array of 32 bytes hash
 * proof_len: length of proof
 */
void mmr_compute_proof_root(MMRVerifyContext *ctx, uint8_t root_hash[HASH_SIZE],
                            uint64_t mmr_size, uint8_t leaf_hash[HASH_SIZE],
                            uint64_t pos, uint8_t proof[][HASH_SIZE],
                            size_t proof_len) {
  MMRHeightPos left_peak = left_peak_height_pos(mmr_size);
  uint64_t peaks_buf[left_peak.height];
  struct MMRPeaks peaks = get_peaks(peaks_buf, left_peak, mmr_size);
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
 * from merkle proof of leaf n to calculate merkle root of n + 1 leaves.
 * this is kinda triky, but by observe the MMR construction graph we know it is
 * possible. https://github.com/jjyr/merkle-mountain-range#construct
 *
 * root_hash: a 32 bytes buf to receive root hash
 * mmr_size: size of the mmr to generate this proof
 * leaf_hash: 32 bytes hash of leaf
 * pos: position of the leaf
 * proof: an array of 32 bytes hash
 * proof_len: length of proof
 * new_leaf_hash: 32 bytes hash of the next leaf
 * new_leaf_pos: the position and mmr_size of the new leaf.
 */
void mmr_compute_new_root_from_last_leaf_proof(
    MMRVerifyContext *ctx, uint8_t root_hash[HASH_SIZE], uint64_t mmr_size,
    uint8_t leaf_hash[HASH_SIZE], uint64_t leaf_pos, uint8_t proof[][HASH_SIZE],
    size_t proof_len, uint8_t new_leaf_hash[HASH_SIZE],
    MMRSizePos new_leaf_pos) {
  if (mmr_size == 0) {
    memcpy(root_hash, new_leaf_hash, HASH_SIZE);
    return;
  }
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
    mmr_compute_proof_root(ctx, root_hash, new_leaf_pos.mmr_size, new_leaf_hash,
                           new_leaf_pos.pos, new_proof, proof_len + 1);
  } else {
    /* new leaf on left branch
     * 1. calculate peak's root from last leaf.
     * 2. use peak's root and remain proof as new_proof, then compute_proof_root
     */
    assert(mmr_size + 1 == new_leaf_pos.mmr_size);
    MMRHeightPos left_peak = left_peak_height_pos(mmr_size);
    uint64_t peaks_buf[left_peak.height];
    struct MMRPeaks peaks = get_peaks(peaks_buf, left_peak, mmr_size);
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
    mmr_compute_proof_root(ctx, root_hash, new_leaf_pos.mmr_size, new_leaf_hash,
                           new_leaf_pos.pos, proof, proof_len);
  }
}
