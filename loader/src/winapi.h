/* Our own implementations of Windows API functions, built on Linux. */
#ifndef WINAPI_H
#define WINAPI_H

#include <stddef.h>

/* Windows x64 calling convention. Every function a Windows program calls
 * must use it, so GCC generates the right register and stack handling. */
#define WINAPI __attribute__((ms_abi))

void  winapi_init(int argc, char **argv, void *image, size_t image_size);
void *winapi_lookup(const char *dll, const char *name);
void  winapi_exit(int code) __attribute__((noreturn));

#endif
