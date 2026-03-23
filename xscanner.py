#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║          XScanner — Next-Gen XSS Framework                ║
║          For authorized penetration testing ONLY          ║
╚═══════════════════════════════════════════════════════════╝
"""

import sys
import asyncio

if sys.version_info < (3, 11):
    print("[!] Python 3.11+ required")
    sys.exit(1)

from cli.interface import main

if __name__ == "__main__":
    main()
