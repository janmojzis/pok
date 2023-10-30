/*
Taken from https://mctiny.org/software.html
- reformated using clang-format
- added pacing_connection_packetssent
- added pacing_connection_packetsreceived
*/

/* See pacing.md for documentation. */

#ifndef pacing_h
#define pacing_h

struct pacing_packet {
    double pacing_packet_storage[8];
};

struct pacing_connection {
    double pacing_connection_storage[128];
};

extern void pacing_connection_init(struct pacing_connection *);
extern void pacing_now_update(struct pacing_connection *);

extern void pacing_packet_init(struct pacing_packet *, long long);
extern void pacing_transmitted(struct pacing_connection *,
                               struct pacing_packet *);
extern void pacing_acknowledged(struct pacing_connection *,
                                struct pacing_packet *);

extern double pacing_whendecongested(struct pacing_connection *, long long);
extern double pacing_whenrto(struct pacing_connection *,
                             struct pacing_packet *);

extern long long
pacing_connection_packetssent(struct pacing_connection *cstorage);
extern long long
pacing_connection_packetsreceived(struct pacing_connection *cstorage);

#endif
