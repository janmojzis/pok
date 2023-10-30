#include "packet.h"
#include "byte.h"
#include "log.h"
#include "nk.h"
#include "mc.h"
#include "server.h"

long long server_phaseK1(unsigned char *packet, long long pos, int flagauth) {

    /*
    query1:
    BLOCKBYTES encrypted box
    - BLOCKBYTES pk block
    */

    struct stack {
        unsigned char key1234query[packet_KEYBYTES];
        unsigned char key1234reply[packet_KEYBYTES];
        unsigned char e0seed[packet_KEYBYTES];
        unsigned char e1seed[packet_KEYBYTES];
        unsigned char cookiekey[packet_KEYBYTES];
        unsigned char e[mc_mctiny_EBYTES];
        unsigned char synd1[mc_mctiny_YBYTES];
        unsigned char hash1[mc_HASHBYTES];
        unsigned char cookie1[mc_mctiny_COOKIE1BLOCKBYTES];
        unsigned char nonce[mc_NONCEBYTES];
        unsigned char box[mc_mctiny_BLOCKBYTES];
    } stack;
    long long ret = -1;
    long long colpos = pos % mc_mctiny_COLBLOCKS;

    /* extract nonce */
    byte_copy(stack.nonce, mc_NONCEBYTES,
              packet + mc_MAGICBYTES + mc_EXTENSIONBYTES);

    /* derive key1234query, key1234reply, e0, e1, cookiekey */
    nk_derivekeys(stack.key1234query, stack.key1234reply, stack.e0seed,
                  stack.e1seed, stack.cookiekey, stack.nonce);

    /* decrypt query1 */
    packet_incoming(packet + mc_HEADERBYTES,
                    mc_mctiny_QUERYK1BYTES - mc_HEADERBYTES);
    if (packet_decrypt(stack.nonce, stack.key1234query) != 0) {
        log_w1("unable to decrypt query1");
        goto cleanup;
    }
    packet_extract(stack.box, mc_mctiny_BLOCKBYTES);
    if (!packet_isok()) {
        log_e1("unable to parse query1");
        goto cleanup;
    }

    /* derive e from eseed */
    if (flagauth) { mc_mctiny_seed2e(stack.e, stack.e1seed); }
    else { mc_mctiny_seed2e(stack.e, stack.e0seed); }

    /* synd1 */
    mc_mctiny_eblock2syndrome(stack.synd1, stack.e, stack.box, colpos);

    /* hash1 */
    mceliece_xof_shake256(stack.hash1, mc_HASHBYTES, stack.box,
                          mc_mctiny_BLOCKBYTES);

    /* cookie1 */
    packet_clear();
    packet_append(stack.hash1, mc_HASHBYTES);
    packet_append(stack.synd1, mc_mctiny_YBYTES);
    packet_encrypt(stack.nonce, stack.cookiekey);
    packet_outgoing(stack.cookie1, mc_mctiny_COOKIE1BLOCKBYTES);

    /* reply1 */
    packet_clear();
    packet_append(stack.cookie1, mc_mctiny_COOKIE1BLOCKBYTES);
    packet_encrypt(stack.nonce, stack.key1234reply);
    byte_copy(packet, mc_MAGICBYTES, mc_MAGICREPLYK);
    byte_copy(packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);
    packet_outgoing(packet + mc_HEADERBYTES,
                    mc_mctiny_REPLYK1BYTES - mc_HEADERBYTES);

    ret = mc_mctiny_REPLYK1BYTES;
cleanup:
    byte_zero(&stack, sizeof stack);
    return ret;
}
