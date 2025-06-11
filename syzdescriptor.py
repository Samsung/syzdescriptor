#!/usr/bin/env python3
import sys, signal
from syzdescriptor.cmd import main

# Silence CPython stacktraces on SIGINT
signal.signal(signal.SIGINT, lambda _a, _b: sys.exit(1))

main()
