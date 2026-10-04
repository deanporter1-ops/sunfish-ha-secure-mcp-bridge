"""Set irreversible Linux no_new_privs before dropping to the coding user.

Separate exec wrapper avoids preexec_fn in the multithreaded credential broker.
No elevated grant or namespace/sandbox relaxation is requested.
"""

import ctypes
import os
import sys

PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
ALLOWED_PROGRAMS = {
    "/usr/local/bin/opencode", "/usr/bin/python3", "/usr/bin/ttyd",
}


def main(arguments):
    if os.getuid() != 0 or not arguments or arguments[0] not in ALLOWED_PROGRAMS:
        raise RuntimeError("Unexpected unprivileged launcher request")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise RuntimeError("no_new_privs could not be established")
    if libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
        raise RuntimeError("no_new_privs was not observed")
    os.execve("/sbin/su-exec", ["/sbin/su-exec", "opencode:opencode", *arguments], dict(os.environ))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception:
        print("Readiness failure category: UNPRIVILEGED_LAUNCH_DENIED", flush=True)
        raise SystemExit(1)
