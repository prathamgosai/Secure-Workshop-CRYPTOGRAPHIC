/* keyio.c - safe key-file writing and reading.
 *
 * Private keys are created with open(..., 0600) so the file is never
 * readable by other users, not even for a moment. fopen() followed by
 * chmod() would leave a window where the file exists with the default
 * permissions (often 0644) and another user could open it.
 */
#include "common.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int write_all(int fd, const unsigned char *b, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, b, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

/* O_NOFOLLOW refuses to write through a symlink an attacker may have planted.
 * fchmod() is still needed: if the file already existed, the mode given to
 * open() is ignored, and the umask may also have removed bits. O_TRUNC runs
 * before any secret is written, so an old looser-mode file is empty when the
 * permissions are tightened. */
static int write_file_mode(const char *path, const unsigned char *buf, size_t len, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    if (fchmod(fd, mode) != 0 || write_all(fd, buf, len) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

int write_file_0600(const char *path, const unsigned char *buf, size_t len) {
    return write_file_mode(path, buf, len, (mode_t)MODE_PRIVATE);
}

int write_file_pub(const char *path, const unsigned char *buf, size_t len) {
    return write_file_mode(path, buf, len, (mode_t)MODE_PUBLIC);
}

/* Reads exactly len bytes. A key file of any other size is rejected, so a
 * truncated or padded file can never be half-loaded as a key. */
int read_file(const char *path, unsigned char *buf, size_t len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (size_t)st.st_size != len) {
        close(fd);
        return -1;
    }

    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (got != len) {
        sodium_memzero(buf, len);   /* never hand back a partial key */
        return -1;
    }
    return 0;
}

int ensure_dir(const char *path, unsigned mode) {
    if (mkdir(path, (mode_t)mode) == 0) return 0;
    if (errno != EEXIST) return -1;
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? 0 : -1;
}

int file_mode(const char *path, unsigned *mode) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *mode = (unsigned)(st.st_mode & 0777);
    return 0;
}

/* 0600 -> "rw-------" (the same text ls -l shows after the file type). */
void mode_string(unsigned mode, char out[10]) {
    static const char flags[] = "rwxrwxrwx";
    for (int i = 0; i < 9; i++)
        out[i] = (mode & (1u << (8 - i))) ? flags[i] : '-';
    out[9] = '\0';
}
