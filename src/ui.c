/* ui.c - terminal presentation helpers. */
#include "ui.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char *C_RESET = "", *C_BOLD = "", *C_DIM = "", *C_RED = "", *C_GREEN = "",
           *C_YELLOW = "", *C_BLUE = "", *C_MAGENTA = "", *C_CYAN = "";

void ui_init(void) {
    /* Line buffering keeps our output in order with child processes (demo). */
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *no_color = getenv("NO_COLOR");
    if (isatty(STDOUT_FILENO) && (no_color == NULL || no_color[0] == '\0')) {
        C_RESET = "\033[0m";  C_BOLD = "\033[1m";   C_DIM = "\033[2m";
        C_RED = "\033[31m";   C_GREEN = "\033[32m"; C_YELLOW = "\033[33m";
        C_BLUE = "\033[34m";  C_MAGENTA = "\033[35m"; C_CYAN = "\033[36m";
    }
}

/* Display width: counts UTF-8 code points and skips ANSI colour sequences. */
size_t ui_width(const char *s) {
    size_t w = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == 0x1b) {
            if (p[1] == '[') {
                p += 2;
                while (*p && !(*p >= 0x40 && *p <= 0x7e)) p++;
                if (!*p) break;
            }
            continue;
        }
        if ((*p & 0xC0) != 0x80) w++;
    }
    return w;
}

static void repeat(const char *s, int n) {
    for (int i = 0; i < n; i++) fputs(s, stdout);
}

static void box_edge(const char *l, const char *r) {
    printf("%s%s", C_CYAN, l);
    repeat("═", UI_BOX);
    printf("%s%s\n", r, C_RESET);
}

void ui_box_top(void)    { box_edge("╔", "╗"); }
void ui_box_sep(void)    { box_edge("╠", "╣"); }
void ui_box_bottom(void) { box_edge("╚", "╝"); }

static void box_emit(const char *text, int centered) {
    int inner = UI_BOX - 2;
    int pad = inner - (int)ui_width(text);
    if (pad < 0) pad = 0;
    int left = centered ? pad / 2 : 0;
    printf("%s║%s %*s%s%*s %s║%s\n", C_CYAN, C_RESET, left, "", text,
           pad - left, "", C_CYAN, C_RESET);
}

void ui_box_line(const char *fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    box_emit(buf, 0);
}

void ui_box_center(const char *fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    box_emit(buf, 1);
}

void ui_box_row(const char *left, const char *right) {
    char buf[512];
    int gap = (UI_BOX - 2) - (int)ui_width(left) - (int)ui_width(right);
    if (gap < 1) gap = 1;
    snprintf(buf, sizeof buf, "%s%*s%s", left, gap, "", right);
    box_emit(buf, 0);
}

void ui_banner(const char *title, const char *subtitle) {
    printf("\n");
    ui_box_top();
    ui_box_center("%s%s%s", C_BOLD, title, C_RESET);
    if (subtitle && *subtitle) ui_box_center("%s%s%s", C_DIM, subtitle, C_RESET);
    ui_box_bottom();
}

void ui_section(const char *title) {
    printf("\n%s%s▶ %s%s\n%s", C_BOLD, C_BLUE, title, C_RESET, C_DIM);
    repeat("─", UI_BOX + 2);
    printf("%s\n", C_RESET);
}

static void status(const char *color, const char *tag, const char *fmt, va_list ap) {
    printf("  %s%s%s ", color, tag, C_RESET);
    vprintf(fmt, ap);
    putchar('\n');
}

void ui_pass(const char *fmt, ...) { va_list ap; va_start(ap, fmt); status(C_GREEN,  "[✓ PASS]", fmt, ap); va_end(ap); }
void ui_fail(const char *fmt, ...) { va_list ap; va_start(ap, fmt); status(C_RED,    "[✗ FAIL]", fmt, ap); va_end(ap); }
void ui_info(const char *fmt, ...) { va_list ap; va_start(ap, fmt); status(C_CYAN,   "[ info ]", fmt, ap); va_end(ap); }
void ui_warn(const char *fmt, ...) { va_list ap; va_start(ap, fmt); status(C_YELLOW, "[! WARN]", fmt, ap); va_end(ap); }

void ui_error(const char *what, const char *reason, const char *action) {
    fflush(stdout);
    fprintf(stderr, "  %s[ERROR]%s %s\n", C_RED, C_RESET, what);
    if (reason) fprintf(stderr, "          Reason: %s\n", reason);
    if (action) fprintf(stderr, "          Action: %s\n", action);
}

/* For PUBLIC values only (public keys, nonces, ciphertext). */
void ui_hex(const char *label, const unsigned char *b, size_t n, size_t max_shown) {
    size_t shown = n < max_shown ? n : max_shown;
    printf("  %-22s %s", label, C_MAGENTA);
    for (size_t i = 0; i < shown; i++) printf("%02x", b[i]);
    printf("%s%s%s (%zu bytes)\n", C_RESET, shown < n ? "…" : "", C_DIM, n);
    fputs(C_RESET, stdout);
}

const char *ui_state_name(int state) {
    static const char *names[] = { "INIT", "AUTH", "SECURE", "TERMINATE" };
    return (state >= 0 && state < 4) ? names[state] : "?";
}

void ui_states(int current) {
    printf("\n  STATE  ");
    for (int s = 0; s < 4; s++) {
        if (s == current) printf("%s%s[ %s ]%s", C_BOLD, C_GREEN, ui_state_name(s), C_RESET);
        else              printf("%s%s%s", C_DIM, ui_state_name(s), C_RESET);
        if (s < 3) printf(" %s→%s ", C_DIM, C_RESET);
    }
    printf("\n");
}

void ui_pause(int enabled) {
    if (!enabled) return;
    printf("\n  %s── press Enter to continue ──%s", C_DIM, C_RESET);
    fflush(stdout);
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }
}
