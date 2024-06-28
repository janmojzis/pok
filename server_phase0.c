#include <randombytes.h>
#include "byte.h"
#include "log.h"
#include "nk.h"
#include "mc.h"
#include "packet.h"
#include "server.h"

long long server_phase0(unsigned char *packet, long long packetlen) {

    struct stack {
        unsigned char key0[3 * packet_KEYBYTES];
        unsigned char key123[packet_KEYBYTES];
        unsigned char eseed[packet_KEYBYTES];
        unsigned char cookiekey[packet_KEYBYTES];
        unsigned char e[mc_mctiny_EBYTESMAX];
        unsigned char nonce[mc_proto_NONCEBYTES];
        unsigned char ciphertext[mc_CIPHERTEXTBYTESMAX];
        unsigned char box[512];
        unsigned char serverpkhash[mc_HASHBYTES];
        struct mc mc;
    } stack;
    long long ret = -1;

    /* extract nonce */
    byte_copy(stack.nonce, mc_proto_NONCEBYTES,
              packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES);

    /* get mctiny variant from the nonce */
    if (!mc_fromid(&stack.mc, stack.nonce[sizeof stack.nonce - 3])) {
        log_w1("unable to parse mctiny variant from the query0 nonce");
        goto cleanup;
    }

    /* check packet length */
    if (stack.mc.mctiny.query0bytes != packetlen) {
        log_w1("bad query0 length");
        goto cleanup;
    }

    /* check nonce */
    if (stack.nonce[sizeof stack.nonce - 2] != 0) {
        log_w1("bad query0 nonce");
        goto cleanup;
    }
    if (stack.nonce[sizeof stack.nonce - 1] != 0) {
        log_w1("bad query0 nonce");
        goto cleanup;
    }

    /* decrypt query0 */
    packet_incoming(packet + mc_proto_HEADERBYTES,
                    stack.mc.mctiny.query0bytes - mc_proto_HEADERBYTES);
    packet_extract(stack.ciphertext, sizeof stack.ciphertext);
    packet_extract(stack.serverpkhash, sizeof stack.serverpkhash);
    mc_keys_dec(stack.key0, stack.ciphertext, stack.serverpkhash);
    if (packet_decrypt(stack.nonce, stack.key0) != 0) {
        log_w1("unable to decrypt query0");
        goto cleanup;
    }
    packet_extract(stack.box, sizeof stack.box);
    if (!packet_isok()) {
        log_w1("unable to parse query0");
        goto cleanup;
    }

    /* generate new nonce, and check if derived eseed is valid */
    do {
        stack.nonce[sizeof stack.nonce - 3] &= mc_IDMASK;
        nk_nonce(stack.nonce);
        nk_derivekeys(stack.key123, stack.eseed, stack.cookiekey, stack.nonce);
    } while (!mc_mctiny_seedisvalid(&stack.mc, stack.eseed));

    log_set_id_hex(stack.nonce, 16);

    stack.nonce[sizeof stack.nonce - 2] += 1; /* bump nonce */

    /* derive e, key123, cookiekey */
    nk_derivekeys(stack.key123, stack.eseed, stack.cookiekey, stack.nonce);
    mc_mctiny_seed2e(&stack.mc, stack.e, stack.eseed);

    /* derive response-key0 and authorization ciphertext */
    if (!mc_keys_authenc(stack.ciphertext, stack.key0 + packet_KEYBYTES,
                         stack.box)) {
        goto cleanup;
    }
    randombytes(stack.key0 + 2 * packet_KEYBYTES, packet_KEYBYTES);
    mceliece_xof_shake256(stack.key0, packet_KEYBYTES, stack.key0,
                          sizeof stack.key0);

    /* reply0 */
    packet_clear();
    packet_append(stack.key123, sizeof stack.key123);
    packet_encrypt(stack.nonce, stack.key0);
    packet_append(stack.ciphertext, sizeof stack.ciphertext);
    packet_append(stack.key0 + 2 * packet_KEYBYTES, packet_KEYBYTES);
    byte_copy(packet + mc_proto_MAGICBYTES + mc_proto_EXTENSIONBYTES,
              mc_proto_NONCEBYTES, stack.nonce);
    packet_outgoing(packet + mc_proto_HEADERBYTES,
                    stack.mc.mctiny.reply0bytes - mc_proto_HEADERBYTES);

    ret = stack.mc.mctiny.reply0bytes;
    log_d3("starting short-term (mctiny) ", stack.mc.name, " key exchange");
cleanup:
    byte_zero(&stack, sizeof stack);
    return ret;
}
