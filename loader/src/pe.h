/* PE (Portable Executable) structures, from Microsoft's published PE format spec.
 * Only the parts the loader needs. All fields are little-endian. */
#ifndef PE_H
#define PE_H

#include <stdint.h>

#define PE_DOS_SIGNATURE        0x5A4D      /* "MZ" */
#define PE_NT_SIGNATURE         0x00004550  /* "PE\0\0" */
#define PE_MACHINE_AMD64        0x8664
#define PE_FILE_DLL             0x2000
#define PE_OPT_MAGIC_PE32PLUS   0x020B

#define PE_SUBSYSTEM_GUI        2
#define PE_SUBSYSTEM_CONSOLE    3

enum {
    PE_DIR_EXPORT    = 0,
    PE_DIR_IMPORT    = 1,
    PE_DIR_BASERELOC = 5,
    PE_DIR_TLS       = 9,
};

#define PE_SCN_MEM_EXECUTE  0x20000000u
#define PE_SCN_MEM_READ     0x40000000u
#define PE_SCN_MEM_WRITE    0x80000000u

#define PE_REL_ABSOLUTE     0
#define PE_REL_HIGHLOW      3
#define PE_REL_DIR64        10

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} pe_data_dir;

typedef struct __attribute__((packed)) {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} pe_file_header;

typedef struct __attribute__((packed)) {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    pe_data_dir DataDirectory[16];
} pe_optional_header64;

typedef struct __attribute__((packed)) {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} pe_section_header;

typedef struct __attribute__((packed)) {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} pe_import_descriptor;

typedef struct __attribute__((packed)) {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
} pe_tls_directory64;

_Static_assert(sizeof(pe_file_header) == 20, "file header size");
_Static_assert(sizeof(pe_optional_header64) == 240, "optional header size");
_Static_assert(sizeof(pe_section_header) == 40, "section header size");
_Static_assert(sizeof(pe_import_descriptor) == 20, "import descriptor size");
_Static_assert(sizeof(pe_tls_directory64) == 40, "TLS directory size");

#endif
