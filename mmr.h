/* Mountain merkle range
 * Reference implementation:
 * https://github.com/nervosnetwork/merkle-mountain-range
 *
 * Copyright 2019 Jiang Jinyang <jjyruby@gmail.com>
 * under MIT license
 */

#ifndef MMR_H
#define MMR_H

#include "stdint.h"
#include "stddef.h"
#define HASH_SIZE 32

/* types */

typedef struct MMRContext {
  /* current mmr_size */
  uint64_t mmr_size;
  /* store tree internal nodes */
  uint8_t (*tree_buf)[HASH_SIZE];
  /* the size of tree_buf
   * a error will occur if mmr_size reach this */
  uint64_t tree_buf_size;
  void (*merge)(uint8_t *dst, uint8_t *right, uint8_t *left);
} MMRContext;

typedef struct MMRVerifyContext {
  void (*merge)(uint8_t *dst, uint8_t *right, uint8_t *left);
} MMRVerifyContext;

typedef struct MMRSizePos {
  uint64_t mmr_size;
  uint64_t pos;
} MMRSizePos;

typedef struct MMRPeaks {
  uint64_t *peaks;
  size_t len;
} MMRPeaks;

typedef struct MMRHeightPos {
  uint32_t height;
  uint64_t pos;
} MMRHeightPos;

/* MMR API */

/* calculate MMRSizePos from leaf index,
 * mmr_size is the size of mmr when index is the last leaf,
 * pos is the position of leaf in internal mmr.
 */
MMRSizePos mmr_compute_pos_by_leaf_index(uint64_t index);

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
                                       uint8_t left[HASH_SIZE]));

/* push a leaf into mmr
 * leaf: a 32 bytes hash represented leaf
 */
int mmr_push(MMRContext *ctx, uint8_t leaf[HASH_SIZE]);

/* get merkle root,
 * return -1 if mmr_size is 0
 * dst: a 32 bytes buf to receive merkle root
 */
int mmr_get_root(MMRContext *ctx, uint8_t dst[HASH_SIZE]);

/* generate merkle proof
 * return -1 if proof length is not enough to receive the proof
 * proof: a array of 32 bytes buf to receive merkle proof
 * proof_max_len: length of proof buf, will be set to the actual len of proof.
 * pos: position of leaf
 */
int mmr_gen_proof(MMRContext *ctx, uint8_t proof[][HASH_SIZE],
                  size_t *proof_max_len, uint64_t pos);

/* Initialize MMRVerifyContext
 * merge: a function to merge left node hash and right node hash
 */
int mmr_initialize_verify_context(MMRVerifyContext *ctx,
                                  void(merge)(uint8_t dst[HASH_SIZE],
                                              uint8_t right[HASH_SIZE],
                                              uint8_t left[HASH_SIZE]));

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
                            size_t proof_len);

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
    MMRSizePos new_leaf_pos);

#endif
