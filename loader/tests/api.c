/* Milestone 1 test: call kernel32 directly, without the C runtime's help. */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const char msg[] = "kernel32 WriteFile works\n";
    DWORD n = 0;
    if (!WriteFile(out, msg, sizeof msg - 1, &n, NULL) || n != sizeof msg - 1)
        return 1;

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    Sleep(20);
    QueryPerformanceCounter(&t1);
    double ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
    if (ms < 15.0)
        return 2;
    printf("Sleep(20) took %.0f ms or more\n", ms > 20.0 ? 20.0 : ms);

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!GetProcAddress(k32, "GetTickCount"))
        return 3;
    if (GetProcAddress(k32, "NoSuchFunction") || GetLastError() != ERROR_PROC_NOT_FOUND)
        return 4;
    printf("GetProcAddress works\n");

    char *heap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
    if (!heap || heap[10] != 0)
        return 5;
    HeapFree(GetProcessHeap(), 0, heap);
    printf("HeapAlloc works\n");

    printf("command line: %s\n", GetCommandLineA());
    ExitProcess(42);
}
