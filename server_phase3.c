#include <mceliece.h>
#include "packet.h"
#include "byte.h"
#include "log.h"
#include "nk.h"
#include "mc.h"
#include "server.h"

long long server_phase3(unsigned char *key, unsigned char *packet,
                        long long packetlen) {

    /*
    query3:
    208B encrypted box
    - 208B synd3
    */

    struct stack {
        unsigned char nonce[mc_proto_NONCEBYTES];
        unsigned char key123[packet_KEYBYTES];
        unsigned char eseed[packet_KEYBYTES];
        unsigned char cookiekey[packet_KEYBYTES];
        unsigned char e[mc_mctiny_EBYTESMAX];
        unsigned char synd3[mc_mctiny_COLBYTESMAX];
        unsigned char ciphertext[mc_CIPHERTEXTBYTESMAX];
        unsigned char key9[packet_KEYBYTES];
        unsigned char cookie9[56]; /* XXX */
        struct mc mc;
    } stack;
    long long ret = -1;

    /* extract nonce */
    byte_copy(stack.nonce, mc_proto_NONCEBYTES,
              packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);

    /* select mctiny variant */
    if (!mc_fromid(&stack.mc, stack.nonce[sizeof stack.nonce - 3])) {
        log_w1("unable to parse mctiny variant from the query2 nonce");
        goto cleanup;
    }

    /* check packet length */
    if (stack.mc.mctiny.query3bytes > packetlen) {
        log_w1("bad query3 length");
        goto cleanup;
    }

    /* check nonce */
    if (stack.nonce[sizeof stack.nonce - 2] != 254) {
        log_w1("bad query3 nonce");
        goto cleanup;
    }
    if (stack.nonce[sizeof stack.nonce - 1] != 255) {
        log_w1("bad query3 nonce");
        goto cleanup;
    }

    /* derive key123, eseed, cookiekey */
    nk_derivekeys(stack.key123, stack.eseed, stack.cookiekey, stack.nonce);

    /* decrypt query3 */
    packet_incoming(packet + mc_proto_HEADERBYTES,
                    stack.mc.mctiny.query3bytes - mc_proto_HEADERBYTES);
    if (packet_decrypt(stack.nonce, stack.key123) != 0) {
        log_w1("unable to decrypt query3 packet");
        goto cleanup;
    }
    packet_extract(stack.synd3, stack.mc.mctiny.colbytes);
    if (!packet_isok()) {
        log_w1("unable to parse query3 packet");
        goto cleanup;
    }

    /* derive e from eseed */
    mc_mctiny_seed2e(&stack.mc, stack.e, stack.eseed);

    mc_mctiny_finalize(&stack.mc, stack.ciphertext, stack.key9, stack.synd3,
                       stack.e);

    /*
    reply3:
    296B encrypted box
    - 56B cookie9
    - 240B ciphertext
    */

    stack.nonce[sizeof stack.nonce - 2] += 1; /* bump nonce */

    /* cookie9 */
    packet_clear();
    packet_append(stack.key9, sizeof stack.key9);
    packet_encrypt(stack.nonce, stack.cookiekey);
    packet_append(stack.nonce, sizeof stack.nonce);
    packet_outgoing(stack.cookie9, sizeof stack.cookie9);

    /* reply3 */
    packet_clear();
    packet_append(stack.cookie9, sizeof stack.cookie9);
    packet_append(stack.ciphertext, sizeof stack.ciphertext);
    packet_encrypt(stack.nonce, stack.key123);
    byte_copy(packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, stack.nonce);
    packet_outgoing(packet + mc_proto_HEADERBYTES,
                    stack.mc.mctiny.reply3bytes - mc_proto_HEADERBYTES);

    mceliece_xof_shake256(key, 2 * packet_KEYBYTES, stack.key9,
                          sizeof stack.key9);

    ret = stack.mc.mctiny.reply3bytes;
    log_d3("finished short-term (mctiny) ", stack.mc.name, " key exchange");
cleanup:
    byte_zero(&stack, sizeof stack);
    return ret;
}
