#include "byte.h"
#include "server.h"
#include "mc.h"
#include "log.h"

/* XXX TODO: add more cache items */
static struct mc_pktree pktree;
static unsigned char pk[mc_PUBLICKEYBYTES];
static unsigned char cacheddata[mc_HASHBYTES];
static int cacheinitialized = 0;

long long server_phaseL(unsigned char *packet, long long packetlen) {

    /*
    queryL:
    */
    unsigned char *p = packet + mc_MAGICBYTES + mc_EXTENSIONBYTES;
    long long level, pos, plen;

    if (packetlen != mc_pktree_QUERYLBYTES) return -1;

    if (!cacheinitialized || !byte_isequal(cacheddata, mc_HASHBYTES, p + 2)) {
        long long pklen;

        pklen = mc_keys_loadpk(pk, p + 2);
        if (pklen < 0) {
            log_w2("unable to load public-key ", log_hex(p + 2, mc_HASHBYTES));
            return -1;
        }
        mc_pktree_pk2tree(&pktree, pk);
        byte_copy(cacheddata, mc_HASHBYTES, p + 2);
        cacheinitialized = 1;
    }
    mc_Levpos_load(&level, &pos, 0, p);
    plen = mc_pktree_block_get(&pktree, p + 2, level, pos);
    if (plen < 0) return -1;

    byte_copy(packet, mc_MAGICBYTES, mc_MAGICREPLYL);
    return mc_MAGICBYTES + mc_EXTENSIONBYTES + 2 + plen;
}
