#include "server.h"
#include "byte.h"
#include "mc.h"

long long server_phaseK(unsigned char *packet, long long packetlen) {

    long long level, position, ret = -1;
    int flagauth;

    mc_Levpos_load(&level, &position, &flagauth, packet + mc_HEADERBYTES - 2);
    if (level < 0 || level > 4) return -1;

    if (level == 0) {
        if (packetlen != mc_mctiny_QUERYK0BYTES) return -1;
        if (position != 0) return -1;
        if (flagauth != 0) return -1;
        ret = server_phaseK0(packet);
    }
    if (level == 1) {
        if (packetlen != mc_mctiny_QUERYK1BYTES) return -1;
        if (position < 0 || position >= mc_mctiny_BLOCKS) return -1;
        if (flagauth < 0 || flagauth > 1) return -1;
        ret = server_phaseK1(packet, position, flagauth);
    }
    if (level == 2) {
        if (packetlen != mc_mctiny_QUERYK2BYTES) return -1;
        if (position < 0 || position >= mc_mctiny_PIECES) return -1;
        if (flagauth < 0 || flagauth > 1) return -1;
        ret = server_phaseK2(packet, position, flagauth);
    }
    if (level == 3) {
        if (packetlen != mc_mctiny_QUERYK3BYTES) return -1;
        if (position < 0 || position >= mc_mctiny_P3PIECES) return -1;
        if (flagauth < 0 || flagauth > 1) return -1;
        ret = server_phaseK3(packet, position, flagauth);
    }
    if (level == 4) {
        if (packetlen != mc_mctiny_QUERYK4BYTES) return -1;
        ret = server_phaseK4(packet);
    }

    if (ret < 0) return ret;
    byte_copy(packet, mc_MAGICBYTES, mc_MAGICREPLYK);
    return ret;
}
