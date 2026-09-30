/* net.c - localhost TCP framing and event output. */
#include "net.h"
#include "json.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int net_listen(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);     /* never reachable from other hosts */
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int net_accept(int lfd) {
    return accept(lfd, NULL, NULL);
}

int net_connect(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int write_full(int fd, const unsigned char *b, size_t n) {
    while (n > 0) {
        ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

static int read_full(int fd, unsigned char *b, size_t n) {
    while (n > 0) {
        ssize_t r = recv(fd, b, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        b += r;
        n -= (size_t)r;
    }
    return 0;
}

int net_send_frame(int fd, uint8_t type, const unsigned char *body, size_t len) {
    if (len + 1 > FRAME_MAX) return -2;
    unsigned char hdr[5];
    uint32_t total = (uint32_t)(len + 1);
    hdr[0] = (unsigned char)(total >> 24); hdr[1] = (unsigned char)(total >> 16);
    hdr[2] = (unsigned char)(total >> 8);  hdr[3] = (unsigned char)total;
    hdr[4] = type;
    if (write_full(fd, hdr, sizeof hdr) != 0) return -1;
    return len ? write_full(fd, body, len) : 0;
}

/* The length prefix is attacker-controlled: it is checked against FRAME_MAX
 * and the caller's buffer before anything is read into memory. */
int net_recv_frame(int fd, uint8_t *type, unsigned char *body, size_t cap, size_t *len) {
    unsigned char hdr[5];
    *len = 0;
    if (read_full(fd, hdr, 4) != 0) return -1;
    uint32_t total = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                     ((uint32_t)hdr[2] << 8) | hdr[3];
    if (total == 0 || total > FRAME_MAX || total - 1 > cap) return -2;
    if (read_full(fd, hdr + 4, 1) != 0) return -1;
    *type = hdr[4];
    if (total > 1 && read_full(fd, body, total - 1) != 0) return -1;
    *len = total - 1;
    return 0;
}

int parse_port(const char *s, uint16_t *port) {
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 1024 || v > 65535) return -1;
    *port = (uint16_t)v;
    return 0;
}

static const char *state_name(channel_state st) {
    static const char *n[] = { "INIT", "AUTH", "SECURE", "TERMINATE" };
    return n[st];
}

void net_log(const char *role, const char *level, channel_state st, const unsigned char *pkt,
             size_t pkt_len, int rc, const char *fmt, ...) {
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (isatty(STDOUT_FILENO)) {
        struct tm tm;
        localtime_r(&ts.tv_sec, &tm);
        printf("%02d:%02d:%02d  %-6s %-9s %-6s %s\n", tm.tm_hour, tm.tm_min, tm.tm_sec,
               role, state_name(st), level, msg);
        fflush(stdout);
        return;
    }
    static char storage[8192];
    json_buf j;
    json_init(&j, storage, sizeof storage);
    json_obj_begin(&j, NULL);
    json_str(&j, "src", role);
    json_int(&j, "ts", (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000);
    json_str(&j, "level", level);
    json_str(&j, "state", state_name(st));
    json_str(&j, "msg", msg);
    if (pkt != NULL && pkt_len >= MIN_PKT_LEN) {
        char seq[24];
        snprintf(seq, sizeof seq, "%llu", (unsigned long long)load_be64(pkt));
        json_obj_begin(&j, "packet");
        json_str(&j, "seq", seq);
        json_int(&j, "length", (long long)pkt_len);
        json_hex(&j, "nonce_hex", pkt + SEQ_LEN, NONCE_LEN);
        json_hex(&j, "tag_hex", pkt + pkt_len - TAG_LEN, TAG_LEN);
        json_int(&j, "rc", rc);
        json_obj_end(&j);
    }
    json_obj_end(&j);
    json_emit(&j);
}
