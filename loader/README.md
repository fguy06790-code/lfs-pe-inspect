# pe-loader

Runs 64-bit Windows console programs on Linux, with no Wine. It is our own
loader and our own Windows API functions, written from Microsoft's public
PE format and API documentation.

## What it does

1. Reads the program's PE headers and copies its sections into memory.
2. Applies relocations if it can't load at its preferred address.
3. Points each imported Windows function at our own Linux implementation
   (`src/winapi.c`). Functions we haven't written yet get a stub that stops
   the program with the function's name, only if it is actually called.
4. Builds the thread block (TEB), process block (PEB), and TLS data that
   Windows code reads through the GS register.
5. Runs TLS callbacks, then starts the program.

## Status: milestone 1

- **Works:** console programs built with mingw-w64 that use `msvcrt`:
  `printf`, arguments, heap, `exit`, plus core `kernel32` calls (`WriteFile`,
  `GetStdHandle`, `Sleep`, timers, `GetProcAddress`, `HeapAlloc`, `ExitProcess`).
- **Not yet:** wide-character startup (`__wgetmainargs`), files, threads,
  the registry, the UCRT (`api-ms-win-crt-*`), exceptions (SEH), DLL loading,
  and GUI programs (`user32`, `gdi32`).

Real Windows tools load but stop at the first missing function:

```text
$ pe-loader /mnt/c/Windows/System32/hostname.exe
pe-loader: the program called msvcrt.dll!__wgetmainargs, which is not implemented yet
```

`PE_LOADER_DEBUG=1 pe-loader program.exe` lists every import and whether it
is implemented, which shows what to write next.

## Build and test

```sh
make
make check          # needs x86_64-w64-mingw32-gcc to build the test .exe files
make install PREFIX=/usr
make install-binfmt # LFS SysVinit: run ./program.exe directly at boot
```

Exit codes: the program's own code, `126` if the file can't be loaded,
`127` if it calls a function that isn't implemented yet.

## Running .exe files directly

`make install-binfmt` installs `/etc/rc.d/init.d/pe-binfmt`, which registers
the PE `MZ` header with the kernel's `binfmt_misc` at boot. After that:

```sh
chmod +x program.exe
./program.exe
```

The kernel needs `CONFIG_BINFMT_MISC`. Don't enable this under WSL, which
already uses `binfmt_misc` to run Windows programs through Windows itself.
