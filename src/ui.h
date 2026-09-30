/* ui.h - terminal presentation helpers (colours, boxes, status lines).
 * Nothing here touches secrets: only public data is ever passed to ui_hex().
 */
#ifndef UI_H
#define UI_H

#include <stddef.h>

#define UI_BOX 64   /* inner width of boxes, in terminal columns */

#if defined(__GNUC__)
#define UI_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define UI_PRINTF(a, b)
#endif

/* Colour codes: empty strings unless stdout is a terminal and NO_COLOR is unset. */
extern const char *C_RESET, *C_BOLD, *C_DIM, *C_RED, *C_GREEN, *C_YELLOW,
                  *C_BLUE, *C_MAGENTA, *C_CYAN;

void ui_init(void);
size_t ui_width(const char *s);

void ui_banner(const char *title, const char *subtitle);
void ui_section(const char *title);
void ui_pass(const char *fmt, ...) UI_PRINTF(1, 2);
void ui_fail(const char *fmt, ...) UI_PRINTF(1, 2);
void ui_info(const char *fmt, ...) UI_PRINTF(1, 2);
void ui_warn(const char *fmt, ...) UI_PRINTF(1, 2);
void ui_error(const char *what, const char *reason, const char *action);

void ui_box_top(void);
void ui_box_sep(void);
void ui_box_bottom(void);
void ui_box_line(const char *fmt, ...) UI_PRINTF(1, 2);
void ui_box_center(const char *fmt, ...) UI_PRINTF(1, 2);
void ui_box_row(const char *left, const char *right);

void ui_hex(const char *label, const unsigned char *b, size_t n, size_t max_shown);
void ui_states(int current);
const char *ui_state_name(int state);
void ui_pause(int enabled);

#endif
