/* pe-loader: load and run a 64-bit Windows console program on Linux.
 *
 * Steps, in the order Windows itself does them:
 *   1. Read and check the PE headers.
 *   2. Reserve memory for the image and copy in the headers and sections.
 *   3. Apply base relocations if the image could not go at its preferred address.
 *   4. Resolve imports: point each imported function at our own implementation,
 *      or at a stub that reports the missing function if it is ever called.
 *   5. Set section memory protections.
 *   6. Build a minimal TEB/PEB (the per-thread and per-process blocks Windows
 *      code reads through the GS register) and the program's TLS block.
 *   7. Run TLS callbacks, then jump to the entry point.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/prctl.h>

#include "pe.h"
#include "winapi.h"

#define PE_LOADER_VERSION "0.1.0"
#define PAGE 4096u

typedef int  (WINAPI *entry_fn)(void);
typedef void (WINAPI *tls_callback_fn)(void *module, uint32_t reason, void *reserved);

static int debug;

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("pe-loader: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(126);
}

static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uintptr_t page_down(uintptr_t v) { return v & ~(uintptr_t)(PAGE - 1); }
static uintptr_t page_up(uintptr_t v)   { return (v + PAGE - 1) & ~(uintptr_t)(PAGE - 1); }

static uint8_t *read_file(const char *path, size_t *len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        die("cannot open %s: %s", path, strerror(errno));
    struct stat st;
    if (fstat(fd, &st) < 0)
        die("cannot stat %s: %s", path, strerror(errno));
    size_t size = (size_t)st.st_size;
    uint8_t *buf = malloc(size ? size : 1);
    if (!buf)
        die("out of memory");
    size_t got = 0;
    while (got < size) {
        ssize_t n = read(fd, buf + got, size - got);
        if (n <= 0)
            die("cannot read %s", path);
        got += (size_t)n;
    }
    close(fd);
    *len = got;
    return buf;
}

/* ---- Stubs for imports we do not implement yet ----------------------------
 * Each stub is a few bytes of machine code:  mov rdi, <name>; mov rax, <fn>; jmp rax
 * so a call reaches unimplemented() with the function's name. Loading succeeds,
 * and only a call to a missing function stops the program, with a clear message. */
#define STUB_SIZE 32
#define STUB_AREA (64 * PAGE)
static uint8_t *stub_area;
static size_t stub_used;

static void __attribute__((noreturn)) unimplemented(const char *what)
{
    fprintf(stderr, "pe-loader: the program called %s, which is not implemented yet\n", what);
    fflush(stderr);
    _exit(127);
}

static void *make_stub(const char *dll, const char *name)
{
    char *what;
    if (asprintf(&what, "%s!%s", dll, name) < 0)
        die("out of memory");
    if (!stub_area) {
        stub_area = mmap(NULL, STUB_AREA, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stub_area == MAP_FAILED)
            die("cannot allocate memory for import stubs");
    }
    if (stub_used + STUB_SIZE > STUB_AREA)
        die("too many unimplemented imports");
    uint8_t *p = stub_area + stub_used;
    stub_used += STUB_SIZE;
    uint64_t arg = (uint64_t)(uintptr_t)what;
    uint64_t fn = (uint64_t)(uintptr_t)unimplemented;
    p[0] = 0x48; p[1] = 0xBF; memcpy(p + 2, &arg, 8);    /* mov rdi, imm64 */
    p[10] = 0x48; p[11] = 0xB8; memcpy(p + 12, &fn, 8);  /* mov rax, imm64 */
    p[20] = 0xFF; p[21] = 0xE0;                           /* jmp rax */
    return p;
}

/* A NUL-terminated string at an RVA, checked to lie inside the image. */
static const char *image_str(const uint8_t *base, uint32_t size, uint32_t rva)
{
    if (rva >= size || !memchr(base + rva, 0, size - rva))
        die("string outside the image (corrupt file)");
    return (const char *)base + rva;
}

static int win_prot(uint32_t chars)
{
    int p = 0;
    if (chars & PE_SCN_MEM_READ)    p |= PROT_READ;
    if (chars & PE_SCN_MEM_WRITE)   p |= PROT_WRITE;
    if (chars & PE_SCN_MEM_EXECUTE) p |= PROT_EXEC | PROT_READ;
    return p;
}

static void apply_relocations(uint8_t *base, const pe_optional_header64 *oh, int64_t delta)
{
    pe_data_dir rd = oh->NumberOfRvaAndSizes > PE_DIR_BASERELOC
                         ? oh->DataDirectory[PE_DIR_BASERELOC] : (pe_data_dir){0, 0};
    if (!rd.VirtualAddress || !rd.Size)
        die("the program must load at 0x%llx, that address is taken, and it has no relocations",
            (unsigned long long)oh->ImageBase);
    if ((uint64_t)rd.VirtualAddress + rd.Size > oh->SizeOfImage)
        die("relocation table outside the image");

    const uint8_t *table = base + rd.VirtualAddress;
    for (uint32_t off = 0; off + 8 <= rd.Size;) {
        uint32_t page = rd32(table + off);
        uint32_t block = rd32(table + off + 4);
        if (block < 8 || off + block > rd.Size)
            die("corrupt relocation table");
        for (uint32_t i = 8; i + 2 <= block; i += 2) {
            uint16_t e = rd16(table + off + i);
            int type = e >> 12;
            uint64_t rva = (uint64_t)page + (e & 0xFFF);
            if (type == PE_REL_ABSOLUTE)
                continue;
            if (rva + 8 > oh->SizeOfImage)
                die("relocation outside the image");
            if (type == PE_REL_DIR64) {
                uint64_t v;
                memcpy(&v, base + rva, 8);
                v += (uint64_t)delta;
                memcpy(base + rva, &v, 8);
            } else if (type == PE_REL_HIGHLOW) {
                uint32_t v;
                memcpy(&v, base + rva, 4);
                v += (uint32_t)delta;
                memcpy(base + rva, &v, 4);
            } else {
                die("unsupported relocation type %d", type);
            }
        }
        off += block;
    }
}

static unsigned resolve_imports(uint8_t *base, const pe_optional_header64 *oh)
{
    unsigned missing = 0;
    uint32_t size = oh->SizeOfImage;
    pe_data_dir id = oh->NumberOfRvaAndSizes > PE_DIR_IMPORT
                         ? oh->DataDirectory[PE_DIR_IMPORT] : (pe_data_dir){0, 0};
    if (!id.VirtualAddress)
        return 0;

    for (uint32_t off = id.VirtualAddress;; off += sizeof(pe_import_descriptor)) {
        if (off + sizeof(pe_import_descriptor) > size)
            die("import table outside the image");
        pe_import_descriptor d;
        memcpy(&d, base + off, sizeof d);
        if (!d.Name && !d.FirstThunk)
            break;
        const char *dll = image_str(base, size, d.Name);
        uint32_t lookup = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;

        for (uint32_t i = 0;; i++) {
            uint64_t lo = (uint64_t)lookup + i * 8ull, iat = (uint64_t)d.FirstThunk + i * 8ull;
            if (lo + 8 > size || iat + 8 > size)
                die("import table outside the image");
            uint64_t thunk;
            memcpy(&thunk, base + lo, 8);
            if (!thunk)
                break;

            void *addr;
            if (thunk >> 63) {
                char ord[16];
                snprintf(ord, sizeof ord, "#%u", (unsigned)(thunk & 0xFFFF));
                addr = make_stub(dll, ord);
                missing++;
                if (debug)
                    fprintf(stderr, "  missing  %s!%s (by ordinal)\n", dll, ord);
            } else {
                const char *fn = image_str(base, size, (uint32_t)thunk + 2);
                addr = winapi_lookup(dll, fn);
                if (!addr) {
                    addr = make_stub(dll, fn);
                    missing++;
                    if (debug)
                        fprintf(stderr, "  missing  %s!%s\n", dll, fn);
                } else if (debug) {
                    fprintf(stderr, "  ok       %s!%s\n", dll, fn);
                }
            }
            uint64_t a = (uint64_t)(uintptr_t)addr;
            memcpy(base + iat, &a, 8);
        }
    }
    if (stub_area && mprotect(stub_area, STUB_AREA, PROT_READ | PROT_EXEC) != 0)
        die("cannot protect import stubs: %s", strerror(errno));
    return missing;
}

/* Windows code finds its thread block (TEB) through the GS segment register.
 * We build one with the fields startup code reads, plus a PEB and TLS array. */
static void setup_thread_block(uint8_t *base, const pe_optional_header64 *oh)
{
    uint8_t *teb = calloc(1, 0x2000);
    uint8_t *peb = calloc(1, 0x1000);
    void **tls_array = calloc(64, sizeof(void *));
    if (!teb || !peb || !tls_array)
        die("out of memory");

    char probe;
    uint64_t stack_base = page_up((uintptr_t)&probe + 0x10000);
    uint64_t stack_limit = stack_base - (8u << 20);
    uint64_t self = (uintptr_t)teb, pebp = (uintptr_t)peb, img = (uintptr_t)base;
    uint64_t pid = (uint64_t)getpid(), tid = (uint64_t)syscall(SYS_gettid);
    uint64_t no_handler = UINT64_MAX, tlsp = (uintptr_t)tls_array;

    memcpy(teb + 0x00, &no_handler, 8);  /* NtTib.ExceptionList */
    memcpy(teb + 0x08, &stack_base, 8);  /* NtTib.StackBase */
    memcpy(teb + 0x10, &stack_limit, 8); /* NtTib.StackLimit */
    memcpy(teb + 0x30, &self, 8);        /* NtTib.Self */
    memcpy(teb + 0x40, &pid, 8);         /* ClientId.UniqueProcess */
    memcpy(teb + 0x48, &tid, 8);         /* ClientId.UniqueThread */
    memcpy(teb + 0x58, &tlsp, 8);        /* ThreadLocalStoragePointer */
    memcpy(teb + 0x60, &pebp, 8);        /* ProcessEnvironmentBlock */
    memcpy(peb + 0x10, &img, 8);         /* ImageBaseAddress */

    /* Static TLS: give the program its own copy of the TLS template. */
    pe_data_dir td = oh->NumberOfRvaAndSizes > PE_DIR_TLS
                         ? oh->DataDirectory[PE_DIR_TLS] : (pe_data_dir){0, 0};
    if (td.VirtualAddress) {
        if ((uint64_t)td.VirtualAddress + sizeof(pe_tls_directory64) > oh->SizeOfImage)
            die("TLS directory outside the image");
        pe_tls_directory64 tls;
        memcpy(&tls, base + td.VirtualAddress, sizeof tls);
        uint64_t lo = (uintptr_t)base, hi = lo + oh->SizeOfImage;
        if (tls.StartAddressOfRawData && (tls.StartAddressOfRawData < lo ||
            tls.EndAddressOfRawData > hi || tls.EndAddressOfRawData < tls.StartAddressOfRawData))
            die("TLS template outside the image");
        size_t raw = (size_t)(tls.EndAddressOfRawData - tls.StartAddressOfRawData);
        uint8_t *block = calloc(1, raw + tls.SizeOfZeroFill + 16);
        if (!block)
            die("out of memory");
        if (raw)
            memcpy(block, (void *)(uintptr_t)tls.StartAddressOfRawData, raw);
        tls_array[0] = block;
        if (tls.AddressOfIndex) {
            if (tls.AddressOfIndex < lo || tls.AddressOfIndex + 4 > hi)
                die("TLS index outside the image");
            uint32_t zero = 0;
            memcpy((void *)(uintptr_t)tls.AddressOfIndex, &zero, 4);
        }
    }

    if (syscall(SYS_arch_prctl, ARCH_SET_GS, teb) != 0)
        die("cannot set the GS base for the thread block: %s", strerror(errno));
}

static void run_tls_callbacks(uint8_t *base, const pe_optional_header64 *oh)
{
    pe_data_dir td = oh->NumberOfRvaAndSizes > PE_DIR_TLS
                         ? oh->DataDirectory[PE_DIR_TLS] : (pe_data_dir){0, 0};
    if (!td.VirtualAddress)
        return;
    pe_tls_directory64 tls;
    memcpy(&tls, base + td.VirtualAddress, sizeof tls);
    if (!tls.AddressOfCallBacks)
        return;
    uint64_t lo = (uintptr_t)base, hi = lo + oh->SizeOfImage;
    for (uint64_t p = tls.AddressOfCallBacks; p >= lo && p + 8 <= hi; p += 8) {
        uint64_t cb;
        memcpy(&cb, (void *)(uintptr_t)p, 8);
        if (!cb)
            break;
        ((tls_callback_fn)(uintptr_t)cb)(base, 1 /* DLL_PROCESS_ATTACH */, NULL);
    }
}

static void usage(void)
{
    fprintf(stderr,
            "usage: pe-loader program.exe [arguments...]\n"
            "Runs a 64-bit Windows console program on Linux.\n"
            "Set PE_LOADER_DEBUG=1 to list which imports are implemented.\n");
}

int main(int argc, char **argv)
{
    if (argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        usage();
        return 2;
    }
    if (!strcmp(argv[1], "--version")) {
        puts("pe-loader " PE_LOADER_VERSION);
        return 0;
    }
    debug = getenv("PE_LOADER_DEBUG") != NULL;
    const char *path = argv[1];

    size_t len;
    uint8_t *file = read_file(path, &len);
    if (len < 0x40 || rd16(file) != PE_DOS_SIGNATURE)
        die("%s is not a Windows program (no MZ header)", path);
    uint32_t pe_off = rd32(file + 0x3C);
    if ((uint64_t)pe_off + 4 + sizeof(pe_file_header) > len || rd32(file + pe_off) != PE_NT_SIGNATURE)
        die("%s is not a PE file", path);

    pe_file_header fh;
    memcpy(&fh, file + pe_off + 4, sizeof fh);
    if (fh.Machine != PE_MACHINE_AMD64)
        die("only 64-bit x86 programs are supported (this one is machine 0x%x)", fh.Machine);
    if (fh.Characteristics & PE_FILE_DLL)
        die("%s is a DLL; programs load DLLs, they cannot run on their own", path);

    pe_optional_header64 oh;
    memset(&oh, 0, sizeof oh);
    size_t opt_off = pe_off + 4 + sizeof fh;
    size_t opt_len = fh.SizeOfOptionalHeader < sizeof oh ? fh.SizeOfOptionalHeader : sizeof oh;
    if (opt_off + opt_len > len)
        die("truncated optional header");
    memcpy(&oh, file + opt_off, opt_len);
    if (oh.Magic != PE_OPT_MAGIC_PE32PLUS)
        die("only PE32+ (64-bit) programs are supported");
    if (oh.Subsystem == PE_SUBSYSTEM_GUI)
        fprintf(stderr, "pe-loader: warning: GUI programs are not supported yet; trying anyway\n");
    if (!oh.SizeOfImage || oh.SizeOfHeaders > oh.SizeOfImage || oh.SizeOfHeaders > len)
        die("bad image size in headers");

    size_t sec_off = opt_off + fh.SizeOfOptionalHeader;
    if (sec_off + (size_t)fh.NumberOfSections * sizeof(pe_section_header) > len)
        die("truncated section table");
    pe_section_header *secs = calloc(fh.NumberOfSections ? fh.NumberOfSections : 1, sizeof *secs);
    if (!secs)
        die("out of memory");
    memcpy(secs, file + sec_off, (size_t)fh.NumberOfSections * sizeof *secs);

    /* Reserve the image at its preferred address, or anywhere and relocate. */
    uint8_t *want = (uint8_t *)(uintptr_t)oh.ImageBase;
    uint8_t *base = mmap(want, oh.SizeOfImage, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (base != MAP_FAILED && base != want) {
        munmap(base, oh.SizeOfImage);
        base = MAP_FAILED;
    }
    if (base == MAP_FAILED) {
        base = mmap(NULL, oh.SizeOfImage, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED)
            die("cannot reserve %u bytes for the image", oh.SizeOfImage);
    }

    memcpy(base, file, oh.SizeOfHeaders);
    for (unsigned i = 0; i < fh.NumberOfSections; i++) {
        const pe_section_header *s = &secs[i];
        uint32_t vsize = s->VirtualSize ? s->VirtualSize : s->SizeOfRawData;
        uint32_t copy = s->SizeOfRawData < vsize ? s->SizeOfRawData : vsize;
        if ((uint64_t)s->VirtualAddress + vsize > oh.SizeOfImage)
            die("section %.8s lies outside the image", s->Name);
        if (copy) {
            if ((uint64_t)s->PointerToRawData + copy > len)
                die("section %.8s is truncated", s->Name);
            memcpy(base + s->VirtualAddress, file + s->PointerToRawData, copy);
        }
    }

    int64_t delta = (int64_t)((uintptr_t)base - oh.ImageBase);
    if (delta)
        apply_relocations(base, &oh, delta);

    winapi_init(argc - 1, argv + 1, base, oh.SizeOfImage);

    if (debug)
        fprintf(stderr, "pe-loader: %s loaded at %p, imports:\n", path, (void *)base);
    unsigned missing = resolve_imports(base, &oh);
    if (debug)
        fprintf(stderr, "pe-loader: %u import(s) not implemented yet\n", missing);

    /* Section protections, if sections are page-aligned. */
    if (oh.SectionAlignment >= PAGE) {
        mprotect(base, page_up(oh.SizeOfHeaders), PROT_READ);
        for (unsigned i = 0; i < fh.NumberOfSections; i++) {
            const pe_section_header *s = &secs[i];
            uint32_t vsize = s->VirtualSize ? s->VirtualSize : s->SizeOfRawData;
            if (!vsize)
                continue;
            uintptr_t start = (uintptr_t)base + s->VirtualAddress;
            if (mprotect((void *)page_down(start), page_up(start + vsize) - page_down(start),
                         win_prot(s->Characteristics)) != 0)
                die("cannot protect section %.8s: %s", s->Name, strerror(errno));
        }
    } else {
        mprotect(base, oh.SizeOfImage, PROT_READ | PROT_WRITE | PROT_EXEC);
    }

    setup_thread_block(base, &oh);
    free(file);
    free(secs);

    run_tls_callbacks(base, &oh);
    entry_fn entry = (entry_fn)(uintptr_t)(base + oh.AddressOfEntryPoint);
    int rc = entry();
    winapi_exit(rc);
}
