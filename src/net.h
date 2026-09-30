/* net.h - localhost TCP transport for the client/server stretch.
 *
 * Frame: [ length 4 B big-endian ][ type 1 B ][ body (length - 1) B ]
 */
#ifndef NET_H
#define NET_H

#include "session.h"

#define NET_DEFAULT_PORT 7700
#define FRAME_MAX (1 + PKT_LEN(SESSION_MSG_MAX))   /* largest frame we accept */

enum {
    MSG_HELLO        = 1,   /* client -> server: client ephemeral pk (32)            */
    MSG_SERVER_HELLO = 2,   /* server -> client: server eph pk (32) | sig (64) | rekey_every (4) */
    MSG_DATA         = 3,   /* either way: sealed packet                              */
    MSG_BYE          = 4,   /* client -> server: close                                */
    MSG_ALERT        = 5    /* server -> client: 1 byte, negated unseal() rc          */
};

int  net_listen(uint16_t port);                 /* binds 127.0.0.1 only */
int  net_accept(int lfd);
int  net_connect(uint16_t port);
int  net_send_frame(int fd, uint8_t type, const unsigned char *body, size_t len);
/* 0 ok, -1 closed / I/O error, -2 frame too large or empty. */
int  net_recv_frame(int fd, uint8_t *type, unsigned char *body, size_t cap, size_t *len);
int  parse_port(const char *s, uint16_t *port);

/* Event output: JSON lines when stdout is not a terminal (dashboard bridge),
 * readable text otherwise. pkt may be NULL. Never pass secrets. */
void net_log(const char *role, const char *level, channel_state st, const unsigned char *pkt,
             size_t pkt_len, int rc, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 7, 8)))
#endif
    ;

#endif
