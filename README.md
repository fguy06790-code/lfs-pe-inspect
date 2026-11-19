# pe-inspect

A read-only inspector for Windows PE files (`.exe`, `.dll`), packaged for
Linux From Scratch. It shows headers, sections, imports, and exports.
It never runs the file it reads.

## Usage

```sh
pe-inspect file.dll              # headers and sections (default)
pe-inspect file.dll --imports    # DLLs and functions it imports
pe-inspect file.dll --exports    # functions it exports, with forwarders
pe-inspect file.exe --all        # everything
```

Exit codes: `0` on success, `1` if the file can't be read or isn't a PE file,
`2` for bad arguments.

## Example

```text
$ pe-inspect ntdll.dll --exports | head -4
Export DLL name: ntdll.dll
Functions: 2523   Named: 2522
```

## Installing on LFS

### Dependencies

- **Required:** Node.js (from BLFS). The tool uses only Node core modules,
  with no npm packages.
- **Build:** `make` and `install` (coreutils), both part of base LFS.

### Build and install

```sh
tar -xf lfs-pe-inspect-<version>.tar.gz
cd lfs-pe-inspect-<version>
make check
make install PREFIX=/usr
```

To stage the install first (for a package manager or a review):

```sh
make install PREFIX=/usr DESTDIR=/tmp/pe-inspect-pkg
```

### Installed files

- `/usr/bin/pe-inspect`
- `/usr/share/doc/pe-inspect/README.md`
- `/usr/share/doc/pe-inspect/LICENSE`

### Removing

```sh
make uninstall PREFIX=/usr
```

## Limits

- Reads PE32 and PE32+ (x86, x64, ARM64). It does not parse resources,
  version info, or certificates yet.
- .NET assemblies built by modern SDKs have no native import table, so
  `--imports` reports none for them. That is correct, not an error.
- A C version with no runtime dependency is possible later, for a base LFS
  system without Node.js.

## License

MIT. See [LICENSE](LICENSE).
