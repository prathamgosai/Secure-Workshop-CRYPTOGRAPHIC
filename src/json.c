/* json.c - minimal JSON writer. */
#include "json.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void json_init(json_buf *j, char *storage, size_t cap) {
    j->buf = storage;
    j->cap = cap;
    j->len = 0;
    j->depth = 0;
    j->first[0] = 1;
    j->overflow = 0;
    if (cap) storage[0] = '\0';
}

static void put(json_buf *j, const char *s, size_t n) {
    if (j->len + n + 1 > j->cap) { j->overflow = 1; return; }
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
}

static void putf(json_buf *j, const char *fmt, ...) {
    char tmp[64];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n > 0) put(j, tmp, (size_t)n < sizeof tmp ? (size_t)n : sizeof tmp - 1);
}

static void put_escaped(json_buf *j, const char *s, size_t n) {
    put(j, "\"", 1);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  put(j, "\\\"", 2); break;
        case '\\': put(j, "\\\\", 2); break;
        case '\n': put(j, "\\n", 2); break;
        case '\r': put(j, "\\r", 2); break;
        case '\t': put(j, "\\t", 2); break;
        default:
            if (c < 0x20 || c == 0x7f) putf(j, "\\u%04x", c);
            else put(j, (const char *)&c, 1);
        }
    }
    put(j, "\"", 1);
}

/* Comma handling and the "key": prefix for the next value. */
static void prefix(json_buf *j, const char *key) {
    if (!j->first[j->depth]) put(j, ",", 1);
    j->first[j->depth] = 0;
    if (key) {
        put_escaped(j, key, strlen(key));
        put(j, ":", 1);
    }
}

static void open_(json_buf *j, const char *key, const char *brace) {
    prefix(j, key);
    put(j, brace, 1);
    if (j->depth + 1 < JSON_MAX_DEPTH) j->first[++j->depth] = 1;
    else j->overflow = 1;
}

static void close_(json_buf *j, const char *brace) {
    put(j, brace, 1);
    if (j->depth > 0) j->depth--;
}

void json_obj_begin(json_buf *j, const char *key) { open_(j, key, "{"); }
void json_obj_end(json_buf *j)                    { close_(j, "}"); }
void json_arr_begin(json_buf *j, const char *key) { open_(j, key, "["); }
void json_arr_end(json_buf *j)                    { close_(j, "]"); }

void json_str(json_buf *j, const char *key, const char *val) {
    prefix(j, key);
    if (val) put_escaped(j, val, strlen(val));
    else put(j, "null", 4);
}

void json_strn(json_buf *j, const char *key, const char *val, size_t n) {
    prefix(j, key);
    put_escaped(j, val, n);
}

void json_int(json_buf *j, const char *key, long long v)  { prefix(j, key); putf(j, "%lld", v); }
void json_num(json_buf *j, const char *key, double v)     { prefix(j, key); putf(j, "%.6g", v); }
void json_bool(json_buf *j, const char *key, int v)       { prefix(j, key); put(j, v ? "true" : "false", v ? 4 : 5); }
void json_null(json_buf *j, const char *key)              { prefix(j, key); put(j, "null", 4); }

void json_hex(json_buf *j, const char *key, const unsigned char *b, size_t n) {
    static const char digits[] = "0123456789abcdef";
    prefix(j, key);
    put(j, "\"", 1);
    for (size_t i = 0; i < n; i++) {
        char h[2] = { digits[b[i] >> 4], digits[b[i] & 15] };
        put(j, h, 2);
    }
    put(j, "\"", 1);
}

void json_emit(json_buf *j) {
    if (j->overflow) {
        fputs("{\"ok\":false,\"error\":\"internal: JSON output buffer overflow\"}\n", stdout);
    } else {
        fwrite(j->buf, 1, j->len, stdout);
        fputc('\n', stdout);
    }
    fflush(stdout);
}
