#!/bin/sh
# Runs pe-loader on the test programs and checks their output and exit codes.
set -u
L=${PE_LOADER:-./pe-loader}
fail=0

check() {  # check NAME CONDITION-DESCRIPTION RESULT
    if [ "$3" -eq 0 ]; then echo "  pass  $1: $2"; else echo "  FAIL  $1: $2"; fail=1; fi
}

echo "== hello.exe"
out=$("$L" tests/hello.exe one "two words"); rc=$?
printf '%s\n' "$out" | sed 's/^/  | /'
[ "$rc" -eq 7 ]; check hello "exit code 7 (got $rc)" $?
printf '%s\n' "$out" | grep -qx 'Hello from a Windows .exe running on Linux!'; check hello "greeting" $?
printf '%s\n' "$out" | grep -qx 'argc=3'; check hello "argc" $?
printf '%s\n' "$out" | grep -qx 'argv\[2\]=two words'; check hello "argument with a space" $?
printf '%s\n' "$out" | grep -qx 'heap works, 42, 1234567890123, 0xff,  3.14'; check hello "printf formats" $?

echo "== api.exe"
out=$("$L" tests/api.exe a "b c"); rc=$?
printf '%s\n' "$out" | sed 's/^/  | /'
[ "$rc" -eq 42 ]; check api "ExitProcess(42) (got $rc)" $?
printf '%s\n' "$out" | grep -qx 'kernel32 WriteFile works'; check api "WriteFile" $?
printf '%s\n' "$out" | grep -qx 'command line: tests/api.exe a "b c"'; check api "GetCommandLineA" $?

echo "== rejects files that are not Windows programs"
"$L" tests/run.sh >/dev/null 2>&1; rc=$?
[ "$rc" -eq 126 ]; check reject "non-PE file exits 126 (got $rc)" $?

if [ "$fail" -eq 0 ]; then echo "all tests passed"; else echo "some tests FAILED"; fi
exit "$fail"
