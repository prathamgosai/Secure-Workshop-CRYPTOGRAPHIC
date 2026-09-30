/* json.h - minimal JSON writer for machine-readable output (engine, bench,
 * TCP mode). Only public values are ever written: never pass secrets here.
 */
#ifndef JSON_H
#define JSON_H

#include <stddef.h>
#include <stdint.h>

#define JSON_MAX_DEPTH 16

typedef struct {
    char *buf;
    size_t len, cap;
    int depth;
    int first[JSON_MAX_DEPTH];
    int overflow;                /* set if anything was truncated */
} json_buf;

void json_init(json_buf *j, char *storage, size_t cap);
void json_obj_begin(json_buf *j, const char *key);   /* key NULL at root / in arrays */
void json_obj_end(json_buf *j);
void json_arr_begin(json_buf *j, const char *key);
void json_arr_end(json_buf *j);
void json_str(json_buf *j, const char *key, const char *val);
void json_strn(json_buf *j, const char *key, const char *val, size_t n);
void json_int(json_buf *j, const char *key, long long v);
void json_num(json_buf *j, const char *key, double v);
void json_bool(json_buf *j, const char *key, int v);
void json_null(json_buf *j, const char *key);
void json_hex(json_buf *j, const char *key, const unsigned char *b, size_t n);  /* PUBLIC data only */
/* Writes the document plus '\n' to stdout and flushes. */
void json_emit(json_buf *j);

#endif
