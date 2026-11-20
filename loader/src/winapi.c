/* Our own implementations of Windows API functions (kernel32 and the msvcrt
 * C runtime), written for Linux from Microsoft's public API documentation.
 *
 * Every function a Windows program calls uses the Windows x64 calling
 * convention (WINAPI = ms_abi). Names are prefixed w_ and mapped to their
 * Windows names in the table at the bottom of this file.
 *
 * Milestone 1 scope: single-threaded console programs. Critical sections are
 * no-ops, and text is treated as Latin-1. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "winapi.h"

extern char **environ;

/* ---- Process state --------------------------------------------------------- */
static int       g_argc;
static char    **g_argv;
static uint8_t  *g_image;
static size_t    g_image_size;
static char     *g_cmdline;
static uint32_t  g_last_error;

/* Data the program imports directly (the import points at the variable). */
static char **w_initenv;
static int    w_fmode;
static int    w_commode;

/* msvcrt's FILE array: stdin, stdout, stderr. Windows FILE is 48 bytes on x64.
 * Programs only pass these pointers back to us, so the contents do not matter. */
#define WIN_FILE_SIZE 48
static uint8_t g_iob[3 * WIN_FILE_SIZE] __attribute__((aligned(16)));

typedef void (WINAPI *void_fn)(void);
typedef int  (WINAPI *int_fn)(void);
static void_fn g_exit_funcs[256];
static int     g_exit_count;

/* ---- Helpers ----------------------------------------------------------------- */
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

static int write_all(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* Map a msvcrt FILE* to a Linux file descriptor (only the standard streams). */
static int file_fd(const void *f)
{
    const uint8_t *p = f;
    if (p >= g_iob && p < g_iob + sizeof g_iob)
        return (int)((p - g_iob) / WIN_FILE_SIZE);
    return -1;
}

/* Console handles from GetStdHandle are small fake values mapped to fds 0-2. */
#define HANDLE_STD_BASE 0x100u
static int handle_fd(const void *h)
{
    uintptr_t v = (uintptr_t)h;
    if (v >= HANDLE_STD_BASE && v < HANDLE_STD_BASE + 3)
        return (int)(v - HANDLE_STD_BASE);
    return -1;
}

static size_t wlen16(const uint16_t *s)
{
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

static char *narrow_dup(const uint16_t *w)
{
    size_t n = wlen16(w);
    char *s = malloc(n + 1);
    if (!s)
        return NULL;
    for (size_t i = 0; i < n; i++)
        s[i] = w[i] > 0xFF ? '?' : (char)w[i];
    s[n] = 0;
    return s;
}

static void run_exit_funcs(void)
{
    while (g_exit_count > 0) {
        void_fn f = g_exit_funcs[--g_exit_count];
        if (f)
            f();
    }
}

static int add_exit_func(void_fn f)
{
    if (g_exit_count >= (int)(sizeof g_exit_funcs / sizeof g_exit_funcs[0]))
        return -1;
    g_exit_funcs[g_exit_count++] = f;
    return 0;
}

/* Find the mapping that contains addr, from /proc/self/maps.
 * Returns its bounds and its protection as a Windows PAGE_* value. */
static int query_region(uintptr_t addr, uintptr_t *start, uintptr_t *end, uint32_t *prot)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long s, e;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) != 3)
            continue;
        if (addr >= s && addr < e) {
            int r = perms[0] == 'r', w = perms[1] == 'w', x = perms[2] == 'x';
            *start = s;
            *end = e;
            *prot = x ? (w ? 0x40 : (r ? 0x20 : 0x10)) : (w ? 0x04 : (r ? 0x02 : 0x01));
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int prot_from_win(uint32_t p)
{
    switch (p & 0xFF) {
    case 0x01: return PROT_NONE;                             /* PAGE_NOACCESS */
    case 0x02: return PROT_READ;                             /* PAGE_READONLY */
    case 0x04: case 0x08: return PROT_READ | PROT_WRITE;     /* READWRITE, WRITECOPY */
    case 0x10: return PROT_EXEC;                             /* PAGE_EXECUTE */
    case 0x20: return PROT_READ | PROT_EXEC;                 /* EXECUTE_READ */
    case 0x40: case 0x80: return PROT_READ | PROT_WRITE | PROT_EXEC;
    default:   return PROT_READ | PROT_WRITE;
    }
}

/* ---- printf-family formatting ------------------------------------------------
 * A Windows x64 va_list is a plain pointer to consecutive 8-byte slots, so we
 * walk it ourselves and format each conversion with Linux snprintf.
 * Windows `long` is 32 bits, so %ld reads 32 bits; %lld and %I64d read 64. */
struct sbuf {
    char  *p;
    size_t len, cap;
};

static int sb_reserve(struct sbuf *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap)
        return 0;
    size_t cap = b->cap ? b->cap : 128;
    while (cap < b->len + extra + 1)
        cap *= 2;
    char *p = realloc(b->p, cap);
    if (!p)
        return -1;
    b->p = p;
    b->cap = cap;
    return 0;
}

static void sb_add(struct sbuf *b, const char *s, size_t n)
{
    if (sb_reserve(b, n) < 0)
        return;
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void sb_printf(struct sbuf *b, const char *spec, ...) __attribute__((format(printf, 2, 3)));
static void sb_printf(struct sbuf *b, const char *spec, ...)
{
    va_list ap, ap2;
    va_start(ap, spec);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, spec, ap);
    va_end(ap);
    if (n > 0 && sb_reserve(b, (size_t)n) == 0) {
        vsnprintf(b->p + b->len, (size_t)n + 1, spec, ap2);
        b->len += (size_t)n;
    }
    va_end(ap2);
}

static uint64_t next_slot(char **ap)
{
    uint64_t v;
    memcpy(&v, *ap, 8);
    *ap += 8;
    return v;
}

static void format_ms(struct sbuf *out, const char *fmt, char *ap)
{
    sb_reserve(out, 0);
    if (out->p)
        out->p[out->len] = 0;
    const char *f = fmt;
    while (*f) {
        if (*f != '%') {
            const char *s = f;
            while (*f && *f != '%')
                f++;
            sb_add(out, s, (size_t)(f - s));
            continue;
        }
        f++;
        if (*f == '%') {
            sb_add(out, "%", 1);
            f++;
            continue;
        }

        /* Rebuild the conversion as a Linux printf spec. */
        char spec[64];
        size_t sl = 0;
        spec[sl++] = '%';
        while (*f && strchr("-+ #0", *f)) {
            if (sl < 16)
                spec[sl++] = *f;
            f++;
        }
        if (*f == '*') {
            sl += (size_t)snprintf(spec + sl, sizeof spec - sl, "%d", (int)(uint32_t)next_slot(&ap));
            f++;
        } else {
            while (*f >= '0' && *f <= '9') {
                if (sl < 32)
                    spec[sl++] = *f;
                f++;
            }
        }
        if (*f == '.') {
            spec[sl++] = '.';
            f++;
            if (*f == '*') {
                sl += (size_t)snprintf(spec + sl, sizeof spec - sl, "%d", (int)(uint32_t)next_slot(&ap));
                f++;
            } else {
                while (*f >= '0' && *f <= '9') {
                    if (sl < 48)
                        spec[sl++] = *f;
                    f++;
                }
            }
        }

        int is64 = 0, wide = 0, half = 0, byte = 0;
        if (f[0] == 'l' && f[1] == 'l') { is64 = 1; f += 2; }
        else if (f[0] == 'l') { wide = 1; f++; }              /* 32-bit long; also %ls / %lc */
        else if (f[0] == 'h' && f[1] == 'h') { byte = 1; f += 2; }
        else if (f[0] == 'h') { half = 1; f++; }
        else if (f[0] == 'I' && f[1] == '6' && f[2] == '4') { is64 = 1; f += 3; }
        else if (f[0] == 'I' && f[1] == '3' && f[2] == '2') { f += 3; }
        else if (f[0] == 'I' || f[0] == 'z' || f[0] == 'j' || f[0] == 't') { is64 = 1; f++; }
        else if (f[0] == 'L' || f[0] == 'q') { is64 = (f[0] == 'q'); f++; }
        else if (f[0] == 'w') { wide = 1; f++; }

        char conv = *f;
        if (!conv)
            break;
        f++;

        switch (conv) {
        case 'd': case 'i': case 'u': case 'x': case 'X': case 'o': {
            uint64_t v = next_slot(&ap);
            if (byte) { spec[sl++] = 'h'; spec[sl++] = 'h'; }
            else if (half) spec[sl++] = 'h';
            else if (is64) { spec[sl++] = 'l'; spec[sl++] = 'l'; }
            spec[sl++] = conv;
            spec[sl] = 0;
            if (is64)
                sb_printf(out, spec, (long long)v);
            else
                sb_printf(out, spec, (int)(uint32_t)v);
            break;
        }
        case 'c': case 'C': {
            uint64_t v = next_slot(&ap);
            int w = (conv == 'C') ? !half : wide;
            char ch = w ? ((uint16_t)v > 0xFF ? '?' : (char)(uint16_t)v) : (char)(uint8_t)v;
            spec[sl++] = 'c';
            spec[sl] = 0;
            sb_printf(out, spec, ch);
            break;
        }
        case 's': case 'S': {
            const void *p = (const void *)(uintptr_t)next_slot(&ap);
            int w = (conv == 'S') ? !half : wide;
            char *tmp = NULL;
            const char *s = "(null)";
            if (p)
                s = w ? (tmp = narrow_dup(p)) ? tmp : "" : (const char *)p;
            spec[sl++] = 's';
            spec[sl] = 0;
            sb_printf(out, spec, s);
            free(tmp);
            break;
        }
        case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A': {
            uint64_t v = next_slot(&ap);
            double d;
            memcpy(&d, &v, 8);
            spec[sl++] = conv;
            spec[sl] = 0;
            sb_printf(out, spec, d);
            break;
        }
        case 'p':
            sb_printf(out, "%016llX", (unsigned long long)next_slot(&ap));
            break;
        case 'n': {
            int *np = (int *)(uintptr_t)next_slot(&ap);
            if (np)
                *np = (int)out->len;
            break;
        }
        default: {
            char lit[2] = { '%', conv };
            sb_add(out, lit, 2);
            break;
        }
        }
    }
}

static int print_to_file(void *f, const char *fmt, char *ap)
{
    struct sbuf b = {0};
    format_ms(&b, fmt, ap);
    int fd = file_fd(f);
    int r = (int)b.len;
    if (fd < 0 || write_all(fd, b.p ? b.p : "", b.len) < 0)
        r = -1;
    free(b.p);
    return r;
}

/* C99 semantics: returns the full length, always NUL-terminates if cap > 0. */
static int print_to_buf(char *dst, size_t cap, const char *fmt, char *ap)
{
    struct sbuf b = {0};
    format_ms(&b, fmt, ap);
    if (cap) {
        size_t n = b.len < cap - 1 ? b.len : cap - 1;
        if (n)
            memcpy(dst, b.p, n);
        dst[n] = 0;
    }
    int r = (int)b.len;
    free(b.p);
    return r;
}

/* msvcrt _snprintf semantics: -1 if the output did not fit. */
static int print_to_buf_ms(char *dst, size_t cap, const char *fmt, char *ap)
{
    struct sbuf b = {0};
    format_ms(&b, fmt, ap);
    int r;
    if (b.len < cap) {
        memcpy(dst, b.p ? b.p : "", b.len + 1);
        r = (int)b.len;
    } else {
        if (cap)
            memcpy(dst, b.p, cap);
        r = b.len == cap ? (int)b.len : -1;
    }
    free(b.p);
    return r;
}

/* ===== kernel32 ================================================================ */

static void WINAPI w_InitializeCriticalSection(void *cs) { (void)cs; }
static int  WINAPI w_InitializeCriticalSectionAndSpinCount(void *cs, uint32_t n) { (void)cs; (void)n; return 1; }
static int  WINAPI w_InitializeCriticalSectionEx(void *cs, uint32_t n, uint32_t fl) { (void)cs; (void)n; (void)fl; return 1; }
static void WINAPI w_EnterCriticalSection(void *cs) { (void)cs; }
static void WINAPI w_LeaveCriticalSection(void *cs) { (void)cs; }
static void WINAPI w_DeleteCriticalSection(void *cs) { (void)cs; }

static uint32_t WINAPI w_GetLastError(void) { return g_last_error; }
static void     WINAPI w_SetLastError(uint32_t e) { g_last_error = e; }

static int WINAPI w_IsDBCSLeadByteEx(uint32_t cp, uint8_t c) { (void)cp; (void)c; return 0; }
static int WINAPI w_IsDBCSLeadByte(uint8_t c) { (void)c; return 0; }

static int WINAPI w_MultiByteToWideChar(uint32_t cp, uint32_t flags, const char *mb, int cb,
                                        uint16_t *wc, int cch)
{
    (void)cp; (void)flags;
    if (!mb || cb == 0) { g_last_error = 87; return 0; }       /* ERROR_INVALID_PARAMETER */
    size_t n = cb < 0 ? strlen(mb) + 1 : (size_t)cb;
    if (cch == 0)
        return (int)n;
    if ((size_t)cch < n) { g_last_error = 122; return 0; }     /* ERROR_INSUFFICIENT_BUFFER */
    for (size_t i = 0; i < n; i++)
        wc[i] = (uint8_t)mb[i];
    return (int)n;
}

static int WINAPI w_WideCharToMultiByte(uint32_t cp, uint32_t flags, const uint16_t *wc, int cch,
                                        char *mb, int cb, const char *def, int *used_def)
{
    (void)cp; (void)flags;
    if (!wc || cch == 0) { g_last_error = 87; return 0; }
    size_t n = cch < 0 ? wlen16(wc) + 1 : (size_t)cch;
    if (used_def)
        *used_def = 0;
    if (cb == 0)
        return (int)n;
    if ((size_t)cb < n) { g_last_error = 122; return 0; }
    for (size_t i = 0; i < n; i++) {
        if (wc[i] > 0xFF) {
            mb[i] = def ? def[0] : '?';
            if (used_def)
                *used_def = 1;
        } else {
            mb[i] = (char)wc[i];
        }
    }
    return (int)n;
}

static void *WINAPI w_SetUnhandledExceptionFilter(void *filter) { (void)filter; return NULL; }

static void WINAPI w_Sleep(uint32_t ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}

static void    *g_tls_slots[64];
static uint64_t g_tls_used;

static uint32_t WINAPI w_TlsAlloc(void)
{
    for (uint32_t i = 0; i < 64; i++)
        if (!(g_tls_used & (1ull << i))) {
            g_tls_used |= 1ull << i;
            g_tls_slots[i] = NULL;
            return i;
        }
    return 0xFFFFFFFFu;                                         /* TLS_OUT_OF_INDEXES */
}
static void *WINAPI w_TlsGetValue(uint32_t i)
{
    if (i >= 64) { g_last_error = 87; return NULL; }
    g_last_error = 0;
    return g_tls_slots[i];
}
static int WINAPI w_TlsSetValue(uint32_t i, void *v)
{
    if (i >= 64) { g_last_error = 87; return 0; }
    g_tls_slots[i] = v;
    return 1;
}
static int WINAPI w_TlsFree(uint32_t i)
{
    if (i >= 64) { g_last_error = 87; return 0; }
    g_tls_used &= ~(1ull << i);
    return 1;
}

static int WINAPI w_VirtualProtect(void *addr, size_t size, uint32_t newp, uint32_t *oldp)
{
    uintptr_t s, e;
    uint32_t old;
    if (!query_region((uintptr_t)addr, &s, &e, &old)) { g_last_error = 487; return 0; }  /* INVALID_ADDRESS */
    if (oldp)
        *oldp = old;
    uintptr_t lo = (uintptr_t)addr & ~(uintptr_t)0xFFF;
    uintptr_t hi = ((uintptr_t)addr + size + 0xFFF) & ~(uintptr_t)0xFFF;
    if (mprotect((void *)lo, hi - lo, prot_from_win(newp)) != 0) { g_last_error = 87; return 0; }
    return 1;
}

/* Fills a 48-byte MEMORY_BASIC_INFORMATION. */
static size_t WINAPI w_VirtualQuery(const void *addr, void *info, size_t len)
{
    if (len < 48) { g_last_error = 24; return 0; }              /* ERROR_BAD_LENGTH */
    uint8_t mbi[48] = {0};
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)0xFFF, s, e;
    uint32_t prot;
    if (query_region(page, &s, &e, &prot)) {
        int in_image = page >= (uintptr_t)g_image && page < (uintptr_t)g_image + g_image_size;
        put64(mbi + 0, page);                                   /* BaseAddress */
        put64(mbi + 8, in_image ? (uintptr_t)g_image : s);      /* AllocationBase */
        put32(mbi + 16, prot);                                  /* AllocationProtect */
        put64(mbi + 24, e - page);                              /* RegionSize */
        put32(mbi + 32, 0x1000);                                /* State = MEM_COMMIT */
        put32(mbi + 36, prot);                                  /* Protect */
        put32(mbi + 40, in_image ? 0x1000000 : 0x20000);        /* MEM_IMAGE / MEM_PRIVATE */
    } else {
        put64(mbi + 0, page);
        put64(mbi + 24, 0x1000);
        put32(mbi + 32, 0x10000);                               /* MEM_FREE */
        put32(mbi + 36, 0x01);                                  /* PAGE_NOACCESS */
    }
    memcpy(info, mbi, 48);
    return 48;
}

static void *WINAPI w_GetStdHandle(uint32_t which)
{
    switch ((int32_t)which) {
    case -10: return (void *)(uintptr_t)(HANDLE_STD_BASE + 0);  /* STD_INPUT_HANDLE */
    case -11: return (void *)(uintptr_t)(HANDLE_STD_BASE + 1);  /* STD_OUTPUT_HANDLE */
    case -12: return (void *)(uintptr_t)(HANDLE_STD_BASE + 2);  /* STD_ERROR_HANDLE */
    default:  g_last_error = 6; return (void *)(intptr_t)-1;    /* INVALID_HANDLE_VALUE */
    }
}

static int WINAPI w_WriteFile(void *h, const void *buf, uint32_t n, uint32_t *written, void *overlapped)
{
    (void)overlapped;
    int fd = handle_fd(h);
    if (written)
        *written = 0;
    if (fd < 0) { g_last_error = 6; return 0; }                /* ERROR_INVALID_HANDLE */
    if (write_all(fd, buf, n) < 0) { g_last_error = 29; return 0; }  /* ERROR_WRITE_FAULT */
    if (written)
        *written = n;
    return 1;
}

static int WINAPI w_WriteConsoleA(void *h, const void *buf, uint32_t n, uint32_t *written, void *reserved)
{
    return w_WriteFile(h, buf, n, written, reserved);
}

static void WINAPI w_ExitProcess(uint32_t code) { _exit((int)code); }

static void *WINAPI w_GetModuleHandleA(const char *name)
{
    if (!name)
        return g_image;
    return (void *)(uintptr_t)0x10000;   /* our built-in DLLs share one fake module handle */
}
static void *WINAPI w_GetModuleHandleW(const uint16_t *name)
{
    return name ? (void *)(uintptr_t)0x10000 : g_image;
}

static void *WINAPI w_GetProcAddress(void *module, const char *name)
{
    (void)module;
    if ((uintptr_t)name < 0x10000) { g_last_error = 127; return NULL; }  /* by ordinal */
    void *p = winapi_lookup(NULL, name);
    if (!p)
        g_last_error = 127;                                     /* ERROR_PROC_NOT_FOUND */
    return p;
}

static char *WINAPI w_GetCommandLineA(void) { return g_cmdline; }

static uint32_t WINAPI w_GetCurrentProcessId(void) { return (uint32_t)getpid(); }
static uint32_t WINAPI w_GetCurrentThreadId(void) { return (uint32_t)syscall(SYS_gettid); }
static void    *WINAPI w_GetCurrentProcess(void) { return (void *)(intptr_t)-1; }
static int      WINAPI w_IsDebuggerPresent(void) { return 0; }

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static uint32_t WINAPI w_GetTickCount(void) { return (uint32_t)(mono_ns() / 1000000ull); }
static uint64_t WINAPI w_GetTickCount64(void) { return mono_ns() / 1000000ull; }
static int WINAPI w_QueryPerformanceCounter(int64_t *c) { *c = (int64_t)mono_ns(); return 1; }
static int WINAPI w_QueryPerformanceFrequency(int64_t *f) { *f = 1000000000; return 1; }

static void WINAPI w_GetSystemTimeAsFileTime(uint64_t *ft)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* FILETIME counts 100 ns intervals since 1601-01-01. */
    *ft = (uint64_t)ts.tv_sec * 10000000ull + (uint64_t)ts.tv_nsec / 100 + 116444736000000000ull;
}

#define FAKE_HEAP ((void *)(uintptr_t)0x20000)
static void *WINAPI w_GetProcessHeap(void) { return FAKE_HEAP; }
static void *WINAPI w_HeapAlloc(void *heap, uint32_t flags, size_t n)
{
    (void)heap;
    return (flags & 0x08) ? calloc(1, n ? n : 1) : malloc(n ? n : 1);  /* HEAP_ZERO_MEMORY */
}
static int   WINAPI w_HeapFree(void *heap, uint32_t flags, void *p) { (void)heap; (void)flags; free(p); return 1; }
static void *WINAPI w_HeapReAlloc(void *heap, uint32_t flags, void *p, size_t n)
{
    (void)heap; (void)flags;
    return realloc(p, n ? n : 1);
}

static uint32_t WINAPI w_GetEnvironmentVariableA(const char *name, char *buf, uint32_t size)
{
    const char *v = getenv(name);
    if (!v) { g_last_error = 203; return 0; }                  /* ERROR_ENVVAR_NOT_FOUND */
    size_t n = strlen(v);
    if (!buf || size <= n)
        return (uint32_t)n + 1;
    memcpy(buf, v, n + 1);
    return (uint32_t)n;
}

/* ===== msvcrt (C runtime) ===================================================== */

static int WINAPI w___getmainargs(int *argc, char ***argv, char ***envp, int glob, void *si)
{
    (void)glob; (void)si;
    *argc = g_argc;
    *argv = g_argv;
    *envp = environ;
    return 0;
}

static void *WINAPI w___iob_func(void) { return g_iob; }
static void  WINAPI w___set_app_type(int t) { (void)t; }
static void  WINAPI w___setusermatherr(void *f) { (void)f; }
static int   WINAPI w____lc_codepage_func(void) { return 0; }
static int   WINAPI w____mb_cur_max_func(void) { return 1; }
static void  WINAPI w__lock(int n) { (void)n; }
static void  WINAPI w__unlock(int n) { (void)n; }
static int  *WINAPI w__errno(void) { return &errno; }

/* Exception dispatch is not implemented; tell the caller to keep searching. */
static int WINAPI w___C_specific_handler(void *rec, void *frame, void *ctx, void *disp)
{
    (void)rec; (void)frame; (void)ctx; (void)disp;
    return 1;                                                   /* ExceptionContinueSearch */
}

static void WINAPI w__initterm(void_fn *begin, void_fn *end)
{
    for (; begin < end; begin++)
        if (*begin)
            (*begin)();
}

static int WINAPI w__initterm_e(int_fn *begin, int_fn *end)
{
    for (; begin < end; begin++)
        if (*begin) {
            int r = (*begin)();
            if (r)
                return r;
        }
    return 0;
}

static void_fn WINAPI w__onexit(void_fn f) { return add_exit_func(f) == 0 ? f : NULL; }
static int     WINAPI w_atexit(void_fn f) { return add_exit_func(f); }

static void WINAPI w_exit(int code) { winapi_exit(code); }
static void WINAPI w__exit(int code) { _exit(code); }
static void WINAPI w__cexit(void) { run_exit_funcs(); }
static void WINAPI w__c_exit(void) { }
static void WINAPI w_abort(void) { abort(); }

static void WINAPI w__amsg_exit(int code)
{
    fprintf(stderr, "runtime error R60%02d\n", code);
    _exit(255);
}

static void *WINAPI w_signal(int sig, void *handler) { (void)sig; (void)handler; return NULL; }

/* Windows struct lconv: ten char* fields, eight char fields, then six wchar_t* fields. */
static uint16_t g_wdot[] = { '.', 0 };
static uint16_t g_wempty[] = { 0 };
static struct {
    char     *s[10];
    char      c[8];
    uint16_t *w[6];
} g_lconv = {
    { ".", "", "", "", "", "", "", "", "", "" },
    { 127, 127, 127, 127, 127, 127, 127, 127 },
    { g_wdot, g_wempty, g_wempty, g_wempty, g_wempty, g_wempty },
};
static void *WINAPI w_localeconv(void) { return &g_lconv; }

static void  *WINAPI w_malloc(size_t n) { return malloc(n); }
static void  *WINAPI w_calloc(size_t n, size_t s) { return calloc(n, s); }
static void  *WINAPI w_realloc(void *p, size_t n) { return realloc(p, n); }
static void   WINAPI w_free(void *p) { free(p); }
static void  *WINAPI w_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
static void  *WINAPI w_memmove(void *d, const void *s, size_t n) { return memmove(d, s, n); }
static void  *WINAPI w_memset(void *d, int c, size_t n) { return memset(d, c, n); }
static int    WINAPI w_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
static size_t WINAPI w_strlen(const char *s) { return strlen(s); }
static int    WINAPI w_strcmp(const char *a, const char *b) { return strcmp(a, b); }
static int    WINAPI w_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
static char  *WINAPI w_strcpy(char *d, const char *s) { return strcpy(d, s); }
static char  *WINAPI w_strncpy(char *d, const char *s, size_t n) { return strncpy(d, s, n); }
static char  *WINAPI w_strcat(char *d, const char *s) { return strcat(d, s); }
static char  *WINAPI w_strchr(const char *s, int c) { return strchr(s, c); }
static char  *WINAPI w_strrchr(const char *s, int c) { return strrchr(s, c); }
static char  *WINAPI w_strstr(const char *h, const char *n) { return strstr(h, n); }
static char  *WINAPI w_strerror(int e) { return strerror(e); }
static int    WINAPI w_atoi(const char *s) { return atoi(s); }
static char  *WINAPI w_getenv(const char *n) { return getenv(n); }
static size_t WINAPI w_wcslen(const uint16_t *s) { return wlen16(s); }

static int WINAPI w_fputc(int c, void *f)
{
    unsigned char ch = (unsigned char)c;
    int fd = file_fd(f);
    return (fd >= 0 && write_all(fd, &ch, 1) == 0) ? ch : -1;  /* EOF */
}
static int WINAPI w_putchar(int c) { return w_fputc(c, g_iob + WIN_FILE_SIZE); }

static int WINAPI w_fputs(const char *s, void *f)
{
    int fd = file_fd(f);
    return (fd >= 0 && write_all(fd, s, strlen(s)) == 0) ? 0 : -1;
}
static int WINAPI w_puts(const char *s)
{
    if (write_all(1, s, strlen(s)) < 0 || write_all(1, "\n", 1) < 0)
        return -1;
    return 0;
}

static size_t WINAPI w_fwrite(const void *p, size_t size, size_t n, void *f)
{
    int fd = file_fd(f);
    if (fd < 0 || !size || !n)
        return 0;
    return write_all(fd, p, size * n) == 0 ? n : 0;
}
static int WINAPI w_fflush(void *f) { (void)f; return 0; }

static int WINAPI w_fprintf(void *f, const char *fmt, ...)
{
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    int r = print_to_file(f, fmt, (char *)ap);
    __builtin_ms_va_end(ap);
    return r;
}
static int WINAPI w_printf(const char *fmt, ...)
{
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    int r = print_to_file(g_iob + WIN_FILE_SIZE, fmt, (char *)ap);
    __builtin_ms_va_end(ap);
    return r;
}
static int WINAPI w_sprintf(char *buf, const char *fmt, ...)
{
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    int r = print_to_buf(buf, SIZE_MAX, fmt, (char *)ap);
    __builtin_ms_va_end(ap);
    return r;
}
static int WINAPI w_snprintf(char *buf, size_t n, const char *fmt, ...)
{
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    int r = print_to_buf(buf, n, fmt, (char *)ap);
    __builtin_ms_va_end(ap);
    return r;
}
static int WINAPI w__snprintf(char *buf, size_t n, const char *fmt, ...)
{
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    int r = print_to_buf_ms(buf, n, fmt, (char *)ap);
    __builtin_ms_va_end(ap);
    return r;
}
static int WINAPI w_vfprintf(void *f, const char *fmt, char *ap) { return print_to_file(f, fmt, ap); }
static int WINAPI w_vprintf(const char *fmt, char *ap) { return print_to_file(g_iob + WIN_FILE_SIZE, fmt, ap); }
static int WINAPI w_vsprintf(char *buf, const char *fmt, char *ap) { return print_to_buf(buf, SIZE_MAX, fmt, ap); }
static int WINAPI w_vsnprintf(char *buf, size_t n, const char *fmt, char *ap) { return print_to_buf(buf, n, fmt, ap); }
static int WINAPI w__vsnprintf(char *buf, size_t n, const char *fmt, char *ap) { return print_to_buf_ms(buf, n, fmt, ap); }

/* ===== Export table ============================================================ */

struct export {
    const char *name;
    void       *addr;
};

#define F(n)       { #n, (void *)w_##n }
#define DATA(n, v) { n, (void *)&v }

static const struct export g_exports[] = {
    /* kernel32 */
    F(InitializeCriticalSection), F(InitializeCriticalSectionAndSpinCount),
    F(InitializeCriticalSectionEx), F(EnterCriticalSection), F(LeaveCriticalSection),
    F(DeleteCriticalSection), F(GetLastError), F(SetLastError), F(IsDBCSLeadByteEx),
    F(IsDBCSLeadByte), F(MultiByteToWideChar), F(WideCharToMultiByte),
    F(SetUnhandledExceptionFilter), F(Sleep), F(TlsAlloc), F(TlsGetValue), F(TlsSetValue),
    F(TlsFree), F(VirtualProtect), F(VirtualQuery), F(GetStdHandle), F(WriteFile),
    F(WriteConsoleA), F(ExitProcess), F(GetModuleHandleA), F(GetModuleHandleW),
    F(GetProcAddress), F(GetCommandLineA), F(GetCurrentProcessId), F(GetCurrentThreadId),
    F(GetCurrentProcess), F(IsDebuggerPresent), F(GetTickCount), F(GetTickCount64),
    F(QueryPerformanceCounter), F(QueryPerformanceFrequency), F(GetSystemTimeAsFileTime),
    F(GetProcessHeap), F(HeapAlloc), F(HeapFree), F(HeapReAlloc), F(GetEnvironmentVariableA),
    /* msvcrt */
    F(__getmainargs), F(__iob_func), F(__set_app_type), F(__setusermatherr),
    F(___lc_codepage_func), F(___mb_cur_max_func), F(_lock), F(_unlock), F(_errno),
    F(__C_specific_handler), F(_initterm), F(_initterm_e), F(_onexit), F(atexit), F(exit),
    F(_exit), F(_cexit), F(_c_exit), F(abort), F(_amsg_exit), F(signal), F(localeconv),
    F(malloc), F(calloc), F(realloc), F(free), F(memcpy), F(memmove), F(memset), F(memcmp),
    F(strlen), F(strcmp), F(strncmp), F(strcpy), F(strncpy), F(strcat), F(strchr), F(strrchr),
    F(strstr), F(strerror), F(atoi), F(getenv), F(wcslen), F(fputc), F(putchar), F(fputs),
    F(puts), F(fwrite), F(fflush), F(fprintf), F(printf), F(sprintf), F(snprintf),
    F(_snprintf), F(vfprintf), F(vprintf), F(vsprintf), F(vsnprintf), F(_vsnprintf),
    DATA("__initenv", w_initenv), DATA("_fmode", w_fmode), DATA("_commode", w_commode),
};

void *winapi_lookup(const char *dll, const char *name)
{
    (void)dll;  /* names are unique across the DLLs we implement */
    for (size_t i = 0; i < sizeof g_exports / sizeof g_exports[0]; i++)
        if (!strcmp(g_exports[i].name, name))
            return g_exports[i].addr;
    return NULL;
}

void winapi_init(int argc, char **argv, void *image, size_t image_size)
{
    g_argc = argc;
    g_argv = argv;
    g_image = image;
    g_image_size = image_size;
    w_initenv = environ;

    /* GetCommandLineA: arguments joined with spaces, quoted when they contain one. */
    size_t cap = 1;
    for (int i = 0; i < argc; i++)
        cap += strlen(argv[i]) + 3;
    g_cmdline = calloc(1, cap);
    if (!g_cmdline)
        return;
    for (int i = 0; i < argc; i++) {
        int quote = strchr(argv[i], ' ') != NULL;
        if (i)
            strcat(g_cmdline, " ");
        if (quote)
            strcat(g_cmdline, "\"");
        strcat(g_cmdline, argv[i]);
        if (quote)
            strcat(g_cmdline, "\"");
    }
}

void winapi_exit(int code)
{
    run_exit_funcs();
    exit(code);
}
