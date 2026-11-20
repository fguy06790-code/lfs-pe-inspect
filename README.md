# lfs-pe-inspect

Windows program support for Linux From Scratch, written from scratch with no
Wine. Two tools:

- **[pe-loader](loader/README.md)** runs 64-bit Windows console programs on
  Linux. It loads the `.exe` itself and supplies our own implementations of
  the Windows functions it calls. Written in C, with no dependencies.
- **pe-inspect** shows what's inside `.exe` and `.dll` files: headers,
  sections, imports, and exports. It never runs the file. Needs Node.js.

The [LFS build script](https://github.com/fguy06790-code/LFS) downloads this
repo and installs both tools into the new system.

## pe-loader

```sh
pe-loader program.exe [arguments...]
```

Milestone 1: console programs that use `msvcrt` and core `kernel32` calls.
See [loader/README.md](loader/README.md) for what works, what doesn't yet,
and how to find the next functions to write.

## pe-inspect

```sh
pe-inspect file.dll              # headers and sections (default)
pe-inspect file.dll --imports    # DLLs and functions it imports
pe-inspect file.dll --exports    # functions it exports, with forwarders
pe-inspect file.exe --all        # everything
```

Exit codes: `0` on success, `1` if the file can't be read or isn't a PE file,
`2` for bad arguments.

```text
$ pe-inspect ntdll.dll --exports | head -2
Export DLL name: ntdll.dll
Functions: 2523   Named: 2522
```

## Installing on LFS

### Dependencies

- **Required:** GCC and make, both part of base LFS.
- **Optional:** Node.js (BLFS), to run `pe-inspect`.
- **For `make check`:** `x86_64-w64-mingw32-gcc`, to build the test `.exe` files.

### Build and install

```sh
git clone https://github.com/fguy06790-code/lfs-pe-inspect.git
cd lfs-pe-inspect
make
make install PREFIX=/usr
make install-binfmt        # optional: run ./program.exe directly (SysVinit)
```

To stage the install first, add `DESTDIR=/tmp/pkg` to the install commands.

### Installed files

- `/usr/bin/pe-loader`
- `/usr/bin/pe-inspect`
- `/usr/share/doc/lfs-pe-inspect/` (README, LICENSE, pe-loader notes)
- `/etc/rc.d/init.d/pe-binfmt` and its `rc3.d`/`rc5.d` links (with `install-binfmt`)

### Removing

```sh
make uninstall PREFIX=/usr
```

## Limits

- pe-loader runs 64-bit console programs only. See its README for the
  functions still to write.
- .NET assemblies built by modern SDKs have no native import table, so
  `pe-inspect --imports` reports none for them. That is correct.

## License

MIT. See [LICENSE](LICENSE).
