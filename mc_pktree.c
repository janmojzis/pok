#include "byte.h"
#include "log.h"
#include "seconds.h"
#include "mc.h"

void mc_pktree_pk2tree(struct mc_pktree *p, const unsigned char *pk) {

    long long l4pos, rowpos, colpos;
    long long l3pos, l3blockpos;
    long long l2pos, l2blockpos;
    long long l1blockpos;

    /* l4 */
    byte_zero(p->l4, sizeof p->l4);
    for (l4pos = 0; l4pos < mc_pktree_L4BLOCKS; ++l4pos) {
        rowpos = l4pos / mc_mctiny_COLBLOCKS;
        colpos = l4pos % mc_mctiny_COLBLOCKS;
        mc_mctiny_pk2block(p->l4[l4pos], pk, rowpos, colpos);
    }

    /* l3 */
    byte_zero(p->l3, sizeof p->l3);
    for (l4pos = 0; l4pos < mc_pktree_L4BLOCKS; ++l4pos) {
        l3pos = l4pos * mc_HASHBYTES / mc_pktree_L3BLOCKBYTES;
        l3blockpos = (l4pos * mc_HASHBYTES) % mc_pktree_L3BLOCKBYTES;
        mceliece_xof_shake256(p->l3[l3pos] + l3blockpos, mc_HASHBYTES,
                              p->l4[l4pos], mc_pktree_L4BLOCKBYTES);
    }

    /* l2 */
    byte_zero(p->l2, sizeof p->l2);
    for (l3pos = 0; l3pos < mc_pktree_L3BLOCKS; ++l3pos) {
        l2pos = l3pos * mc_HASHBYTES / mc_pktree_L2BLOCKBYTES;
        l2blockpos = (l3pos * mc_HASHBYTES) % mc_pktree_L2BLOCKBYTES;
        mceliece_xof_shake256(p->l2[l2pos] + l2blockpos, mc_HASHBYTES,
                              p->l3[l3pos], mc_pktree_L3BLOCKBYTES);
    }

    /* l1 */
    byte_zero(p->l1, sizeof p->l1);
    for (l2pos = 0; l2pos < mc_pktree_L2BLOCKS; ++l2pos) {
        l1blockpos = (l2pos * mc_HASHBYTES) % mc_pktree_L1BLOCKBYTES;
        mceliece_xof_shake256(p->l1 + l1blockpos, mc_HASHBYTES, p->l2[l2pos],
                              mc_pktree_L2BLOCKBYTES);
    }

    /* l0 */
    mceliece_xof_shake256(p->l0, mc_HASHBYTES, p->l1, mc_pktree_L1BLOCKBYTES);
}

static long long blockbytes[5] = {
    mc_HASHBYTES, mc_pktree_L1BLOCKBYTES, mc_pktree_L2BLOCKBYTES,
    mc_pktree_L3BLOCKBYTES, mc_pktree_L4BLOCKBYTES};

static long long blocks[5] = {1, 1, mc_pktree_L2BLOCKS, mc_pktree_L3BLOCKS,
                              mc_pktree_L4BLOCKS};

static int pktree_block_check(long long level, long long pos,
                              long long datalen) {

    if (level < 0 || level > 4) {
        log_w3("invalid public-key block: level = ", log_num(level),
               ", level must be in the range <0-4>");
        return 0;
    }

    if (pos < 0 || pos >= blocks[level]) {
        log_w7("invalid public-key block: level = ", log_num(level),
               ", position = ", log_num(pos),
               ", position must be in the range <0-",
               log_num(blocks[level] - 1), ">");
        return 0;
    }
    if (datalen != blockbytes[level]) {
        log_w6("invalid public-key block: level = ", log_num(level),
               ", blockbytes = ", log_num(datalen), ", blockbytes must be ",
               log_num(blockbytes[level]));
        return 0;
    }
    return 1;
}

int mc_pktree_block_put(struct mc_pktree *p, long long level, long long pos,
                        unsigned char *data, long long datalen) {

    unsigned char h[mc_HASHBYTES];
    long long blockpos, blockid;

    if (!pktree_block_check(level, pos, datalen)) return 0;

    if (level == 0) {
        byte_copy(p->l0, datalen, data);
        return 1;
    }

    if (level == 1) {
        mceliece_xof_shake256(h, mc_HASHBYTES, data, datalen);
        if (!byte_isequal(p->l0, mc_HASHBYTES, h)) {
            log_w2("invalid public-key block: l1 block hash doesn't match l0 "
                   "hash ",
                   log_hex(p->l0, mc_HASHBYTES));
            return 0;
        }
        byte_copy(p->l1, datalen, data);
        return 1;
    }

    if (level == 2) {
        blockpos = (mc_HASHBYTES * pos) % mc_pktree_L1BLOCKBYTES;
        mceliece_xof_shake256(h, mc_HASHBYTES, data, datalen);
        if (!byte_isequal(p->l1 + blockpos, mc_HASHBYTES, h)) {
            log_w2("invalid public-key block: l2 block hash doesn't match l1 "
                   "hash ",
                   log_hex(p->l1 + blockpos, mc_HASHBYTES));
            return 0;
        }
        byte_copy(p->l2[pos], datalen, data);
        return 1;
    }

    if (level == 3) {
        blockpos = (mc_HASHBYTES * pos) % mc_pktree_L2BLOCKBYTES;
        blockid = (mc_HASHBYTES * pos) / mc_pktree_L2BLOCKBYTES;
        mceliece_xof_shake256(h, mc_HASHBYTES, data, datalen);
        if (!byte_isequal(p->l2[blockid] + blockpos, mc_HASHBYTES, h)) {
            log_w2("invalid public-key block: l3 block hash doesn't match l2 "
                   "hash ",
                   log_hex(p->l2[blockid] + blockpos, mc_HASHBYTES));
            return 0;
        }
        byte_copy(p->l3[pos], datalen, data);
        return 1;
    }
    if (level == 4) {
        blockpos = (mc_HASHBYTES * pos) % mc_pktree_L3BLOCKBYTES;
        blockid = (mc_HASHBYTES * pos) / mc_pktree_L3BLOCKBYTES;
        mceliece_xof_shake256(h, mc_HASHBYTES, data, datalen);
        if (!byte_isequal(p->l3[blockid] + blockpos, mc_HASHBYTES, h)) {
            log_w2("invalid public-key block: l4 block hash doesn't match l3 "
                   "hash ",
                   log_hex(p->l3[blockid] + blockpos, mc_HASHBYTES));
            return 0;
        }
        byte_copy(p->l4[pos], datalen, data);
        return 1;
    }
    return 0;
}

static void mc_pktree_block2pk(unsigned char *out, const unsigned char *block,
                               long long rowpos, long long colpos) {
    long long i, j;
    unsigned char bit;

    colpos *= mc_mctiny_X;
    rowpos *= mc_mctiny_Y;

    for (i = 0; i < mc_mctiny_Y; ++i) {
        if (rowpos + i < 0) continue;
        if (rowpos + i >= mc_mctiny_COLBITS) continue;

        for (j = 0; j < mc_mctiny_X; ++j) {
            if (colpos + j < 0) continue;
            if (colpos + j >= mc_mctiny_ROWBITS) continue;

            bit = block[(i * mc_mctiny_X + j) / 8];
            bit = 1 & (bit >> ((i * mc_mctiny_X + j) & 7));
            bit <<= ((colpos + j) & 7);
            out[mc_mctiny_ROWBYTES * (rowpos + i) + (colpos + j) / 8] |= bit;
        }
    }
}

void mc_pktree_to_pk(struct mc_pktree *p, unsigned char *pk) {

    long long l4pos, rowpos, colpos, i;

    for (i = 0; i < mc_PUBLICKEYBYTES; ++i) pk[i] = 0;

    for (l4pos = 0; l4pos < mc_pktree_L4BLOCKS; ++l4pos) {
        rowpos = l4pos / mc_mctiny_COLBLOCKS;
        colpos = l4pos % mc_mctiny_COLBLOCKS;
        mc_pktree_block2pk(pk, p->l4[l4pos], rowpos, colpos);
    }
}

static long long mc_pktree_l0_get(struct mc_pktree *p, unsigned char *data) {
    byte_copy(data, mc_HASHBYTES, p->l0);
    return mc_HASHBYTES;
}

static long long mc_pktree_l1_get(struct mc_pktree *p, unsigned char *data) {
    byte_copy(data, mc_pktree_L1BLOCKBYTES, p->l1);
    return mc_pktree_L1BLOCKBYTES;
}

static long long mc_pktree_l2_get(struct mc_pktree *p, unsigned char *data,
                                  long long pos) {
    if (pos < 0) return -1;
    if (pos >= mc_pktree_L2BLOCKS) return -1;
    byte_copy(data, mc_pktree_L2BLOCKBYTES, p->l2[pos]);
    return mc_pktree_L2BLOCKBYTES;
}

static long long mc_pktree_l3_get(struct mc_pktree *p, unsigned char *data,
                                  long long pos) {
    if (pos < 0) return -1;
    if (pos >= mc_pktree_L3BLOCKS) return -1;
    byte_copy(data, mc_pktree_L3BLOCKBYTES, p->l3[pos]);
    return mc_pktree_L3BLOCKBYTES;
}

static long long mc_pktree_l4_get(struct mc_pktree *p, unsigned char *data,
                                  long long pos) {
    if (pos < 0) return -1;
    if (pos >= mc_pktree_L4BLOCKS) return -1;
    byte_copy(data, mc_pktree_L4BLOCKBYTES, p->l4[pos]);
    return mc_pktree_L4BLOCKBYTES;
}

long long mc_pktree_block_get(struct mc_pktree *p, unsigned char *data,
                              long long level, long long pos) {
    if (level == 0) return mc_pktree_l0_get(p, data);
    if (level == 1) return mc_pktree_l1_get(p, data);
    if (level == 2) return mc_pktree_l2_get(p, data, pos);
    if (level == 3) return mc_pktree_l3_get(p, data, pos);
    if (level == 4) return mc_pktree_l4_get(p, data, pos);
    return -1;
}
