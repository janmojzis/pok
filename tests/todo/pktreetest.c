#include "mc.h"
#include "byte.h"
#include "log.h"

static struct g {
    unsigned char sk[mc6688128_SECRETKEYBYTES];
    unsigned char pk[mc6688128_PUBLICKEYBYTES];
    unsigned char pk1[mc6688128_PUBLICKEYBYTES];
    struct mc6688128_pktree pktree;
    struct mc6688128_pktree pktree1;
} g;


int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    long long rowpos, colpos, l4pos, i, j;
    int ret;

    mc6688128_keypair(g.pk, g.sk);
    mc6688128_pk2tree(&g.pktree, g.pk);

    for (i = (mc6688128_PUBLICKEYBYTES - 32); i < mc6688128_PUBLICKEYBYTES; ++i) {
        for (j = 0; j < 8; ++j) {

            byte_copy(g.pk1, mc6688128_PUBLICKEYBYTES, g.pk);
            g.pk1[i] ^= 1 << j;

            ret = 0;
            for (l4pos = 0; l4pos < mc6688128_L4BLOCKS; ++l4pos) {
                rowpos = l4pos / mc6688128_COLBLOCKS;
                colpos = l4pos % mc6688128_COLBLOCKS;
                mc6688128_pk2block(g.pktree1.l4[l4pos], g.pk1, rowpos, colpos);
                ret |= byte_isequal(g.pktree1.l4[l4pos], mc6688128_L4BLOCKBYTES, g.pktree.l4[l4pos]);
            }
            if (!ret) {
                log_f1("Oops, the public key is different but the blocks are identical !!!");
                return 1;
            }


#if 0
            byte_zero(g.pk2, sizeof g.pk2);
            for (l4pos = 0; l4pos < mc6688128_L4BLOCKS; ++l4pos) {
                rowpos = l4pos / mc6688128_COLBLOCKS;
                colpos = l4pos % mc6688128_COLBLOCKS;
                mc6688128_pktree_block2pk(g.pk2, g.pktree.l4[l4pos], rowpos, colpos);
            }
#endif

        }
    }
    return 0;
}
