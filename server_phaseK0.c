#include <randombytes.h>
#include "byte.h"
#include "log.h"
#include "nk.h"
#include "mc.h"
#include "packet.h"
#include "server.h"

long long server_phaseK0(unsigned char *packet) {

    struct stack {
        unsigned char key0query[packet_KEYBYTES];
        unsigned char key0reply[packet_KEYBYTES];
        unsigned char key1234query[packet_KEYBYTES];
        unsigned char key1234reply[packet_KEYBYTES];
        unsigned char e0seed[packet_KEYBYTES];
        unsigned char e1seed[packet_KEYBYTES];
        unsigned char cookiekey[packet_KEYBYTES];
        unsigned char e0[mc_mctiny_EBYTES];
        unsigned char e1[mc_mctiny_EBYTES];
        unsigned char nonce[mc_NONCEBYTES];
        unsigned char ciphertext[mc_CIPHERTEXTBYTES];
        unsigned char box[512];
        unsigned char serverpkhash[mc_HASHBYTES];
    } stack;
    long long ret = -1;

    /* extract nonce */
    byte_copy(stack.nonce, mc_NONCEBYTES,
              packet + mc_MAGICBYTES + mc_EXTENSIONBYTES);

    /* decrypt query0 */
    packet_incoming(packet + mc_HEADERBYTES,
                    mc_mctiny_QUERYK0BYTES - mc_HEADERBYTES);
    packet_extract(stack.ciphertext, sizeof stack.ciphertext);
    packet_extract(stack.serverpkhash, sizeof stack.serverpkhash);
    mc_keys_dec(stack.key0query, stack.ciphertext, stack.serverpkhash);
    mc_derivekeys(stack.key0query, stack.key0reply, stack.key0query);

    if (packet_decrypt(stack.nonce, stack.key0query) != 0) {
        log_w1("unable to decrypt query0");
        goto cleanup;
    }
    packet_extract(stack.box, sizeof stack.box);
    if (!packet_isok()) {
        log_w1("unable to parse query0");
        goto cleanup;
    }

    /* generate new nonce, and check if derived e0seed and e1seed are valid */
    do {
        nk_nonce(stack.nonce);
        nk_derivekeys(stack.key1234query, stack.key1234reply, stack.e0seed,
                      stack.e1seed, stack.cookiekey, stack.nonce);
    } while (!mc_mctiny_seedisvalid(stack.e0seed) ||
             !mc_mctiny_seedisvalid(stack.e1seed));

    /*
        log_set_id_hex(stack.nonce, 16);
    */

    /* derive key1234query, key1234reply, e0, e1, cookiekey */
    nk_derivekeys(stack.key1234query, stack.key1234reply, stack.e0seed,
                  stack.e1seed, stack.cookiekey, stack.nonce);
    mc_mctiny_seed2e(stack.e0, stack.e0seed);
    mc_mctiny_seed2e(stack.e1, stack.e1seed);

    /* reply0 */
    packet_clear();
    packet_append(stack.key1234query, packet_KEYBYTES);
    packet_append(stack.key1234reply, packet_KEYBYTES);
    packet_encrypt(stack.nonce, stack.key0reply);
    byte_copy(packet, mc_MAGICBYTES, mc_MAGICREPLYK);
    byte_copy(packet + mc_MAGICBYTES + mc_EXTENSIONBYTES, mc_NONCEBYTES,
              stack.nonce);
    packet_outgoing(packet + mc_HEADERBYTES,
                    mc_mctiny_REPLYK0BYTES - mc_HEADERBYTES);

    ret = mc_mctiny_REPLYK0BYTES;
cleanup:
    byte_zero(&stack, sizeof stack);
    return ret;
}
